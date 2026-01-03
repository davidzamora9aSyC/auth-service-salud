import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
} from '@nestjs/common';
import { Account, AccountRole, AccountStatus, OnboardingStatus, Prisma, TwoFactorMethod } from '@prisma/client';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, randomBytes, randomInt, randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { authenticator } from 'otplib';
import { decode, sign, SignOptions, verify } from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import { TwoFactorSetupDto } from './dto/two-factor-setup.dto';
import { TwoFactorCodeDto } from './dto/two-factor-code.dto';
import { NotificationsService } from '../notifications/notifications.service';
import { RecoveryStartDto } from './dto/recovery-start.dto';
import { RecoveryVerifyDto } from './dto/recovery-verify.dto';
import { RecoveryCompleteDto } from './dto/recovery-complete.dto';
import { OAuthAuthorizeDto } from './dto/oauth-authorize.dto';
import { OAuthTokenDto } from './dto/oauth-token.dto';
import { RabbitmqService } from './rabbitmq.service';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private readonly privateKey: Buffer;
  private readonly publicKey: ReturnType<typeof createPublicKey>;
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly challengeTtl: number;
  private readonly recoveryCodeTtl: number;
  private readonly recoveryResetTtl: number;
  private readonly recoveryMaxAttempts: number;
  private readonly recoveryLinkBase: string;
  private readonly oauthCodeTtl: number;
  private readonly oauthClientTtl: number;
  private readonly googleClientId?: string;
  private readonly googleClientSecret?: string;
  private readonly googleRedirectUri?: string;
  private readonly googleScopes: string;
  private readonly googleStateTtl: number;
  private readonly googleSuccessRedirect?: string;
  private readonly googleErrorRedirect?: string;
  private readonly googleStateStore = new Map<string, { role: AccountRole; redirect?: string; createdAt: number }>();
  private readonly appleClientId?: string;
  private readonly appleTeamId?: string;
  private readonly appleKeyId?: string;
  private readonly appleRedirectUri?: string;
  private readonly appleScopes: string;
  private readonly appleStateTtl: number;
  private readonly appleSuccessRedirect?: string;
  private readonly appleErrorRedirect?: string;
  private readonly applePrivateKey?: string;
  private readonly appleStateStore = new Map<string, { role: AccountRole; redirect?: string; createdAt: number }>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly notifications: NotificationsService,
    private readonly rabbitmq: RabbitmqService,
  ) {
    const privateKeyPath = this.config.get<string>('JWT_PRIVATE_KEY_PATH');
    if (!privateKeyPath) {
      throw new Error('JWT_PRIVATE_KEY_PATH is not configured');
    }
    this.privateKey = readFileSync(privateKeyPath);
    this.publicKey = createPublicKey(this.privateKey);
    this.accessTtl = parseInt(
      this.config.get<string>('ACCESS_TOKEN_TTL', '900'),
      10,
    );
    this.refreshTtl = parseInt(
      this.config.get<string>('REFRESH_TOKEN_TTL', '604800'),
      10,
    );
    this.challengeTtl = parseInt(
      this.config.get<string>('LOGIN_CHALLENGE_TTL', '300'),
      10,
    );
    this.recoveryCodeTtl = parseInt(
      this.config.get<string>('RECOVERY_CODE_TTL', '600'),
      10,
    );
    this.recoveryResetTtl = parseInt(
      this.config.get<string>('RECOVERY_RESET_TTL', '900'),
      10,
    );
    this.recoveryMaxAttempts = parseInt(
      this.config.get<string>('RECOVERY_MAX_ATTEMPTS', '5'),
      10,
    );
    this.recoveryLinkBase =
      this.config.get<string>('RECOVERY_LINK_BASE') ??
      'http://localhost:3007/recover';
    this.oauthCodeTtl = parseInt(
      this.config.get<string>('OAUTH_CODE_TTL', '300'),
      10,
    );
    this.oauthClientTtl = parseInt(
      this.config.get<string>('OAUTH_CLIENT_TTL', `${this.accessTtl}`),
      10,
    );
    this.googleClientId = this.config.get<string>('GOOGLE_CLIENT_ID');
    this.googleClientSecret = this.config.get<string>('GOOGLE_CLIENT_SECRET');
    this.googleRedirectUri = this.config.get<string>('GOOGLE_REDIRECT_URI');
    this.googleScopes =
      this.config.get<string>('GOOGLE_OAUTH_SCOPES') ??
      'openid email profile';
    this.googleStateTtl = parseInt(
      this.config.get<string>('GOOGLE_OAUTH_STATE_TTL', '600'),
      10,
    );
    this.googleSuccessRedirect =
      this.config.get<string>('GOOGLE_OAUTH_SUCCESS_REDIRECT');
    this.googleErrorRedirect =
      this.config.get<string>('GOOGLE_OAUTH_ERROR_REDIRECT');
    this.appleClientId = this.config.get<string>('APPLE_CLIENT_ID');
    this.appleTeamId = this.config.get<string>('APPLE_TEAM_ID');
    this.appleKeyId = this.config.get<string>('APPLE_KEY_ID');
    this.appleRedirectUri = this.config.get<string>('APPLE_REDIRECT_URI');
    this.appleScopes =
      this.config.get<string>('APPLE_OAUTH_SCOPES') ??
      'name email';
    this.appleStateTtl = parseInt(
      this.config.get<string>('APPLE_OAUTH_STATE_TTL', '600'),
      10,
    );
    this.appleSuccessRedirect =
      this.config.get<string>('APPLE_OAUTH_SUCCESS_REDIRECT');
    this.appleErrorRedirect =
      this.config.get<string>('APPLE_OAUTH_ERROR_REDIRECT');
    const appleKeyPath = this.config.get<string>('APPLE_PRIVATE_KEY_PATH');
    if (appleKeyPath) {
      this.applePrivateKey = readFileSync(appleKeyPath, 'utf-8');
    } else {
      const inlineKey = this.config.get<string>('APPLE_PRIVATE_KEY');
      this.applePrivateKey = inlineKey?.replace(/\\n/g, '\n');
    }
  }

  async register(dto: RegisterDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = this.normalizePhoneNumber(dto.phoneNumber);
    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      throw new ConflictException('El email ya esta registrado');
    }
    const existingPhone = await this.prisma.account.findUnique({
      where: { phoneNumber: normalizedPhone },
    });
    if (existingPhone) {
      throw new ConflictException('El numero de telefono ya esta registrado');
    }
    const salt = randomBytes(24).toString('hex');
    const passwordHash = await argon2.hash(dto.password + salt, {
      type: argon2.argon2id,
    });
    const doctorId =
      dto.role === AccountRole.DOCTOR ? randomUUID() : null;
    const onboardingStatus =
      dto.role === AccountRole.DOCTOR
        ? OnboardingStatus.PENDING
        : OnboardingStatus.COMPLETE;
    let account: Account;
    try {
      account = await this.prisma.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: dto.role,
          subjectId: dto.subjectId ?? null,
          phoneNumber: normalizedPhone,
          doctorId,
          onboardingStatus,
        },
      });
    } catch (error) {
      if (error instanceof Prisma.PrismaClientKnownRequestError && error.code === 'P2002') {
        const targets = Array.isArray(error.meta?.target) ? error.meta.target : [];
        if (targets.includes('email')) {
          throw new ConflictException('El email ya esta registrado');
        }
        if (targets.includes('phoneNumber')) {
          throw new ConflictException('El numero de telefono ya esta registrado');
        }
        throw new ConflictException('La cuenta ya existe');
      }
      throw error;
    }
    await this.notifications.sendRegistrationWhatsapp({
      phoneNumber: normalizedPhone,
      email: account.email,
    });
    if (account.role === AccountRole.DOCTOR && account.doctorId) {
      await this.rabbitmq.publishAuthEvent({
        type: 'AuthUserRegistered',
        routingKey: 'auth.user_registered',
        data: {
          authUserId: account.id,
          role: account.role,
          doctorId: account.doctorId,
          email: account.email,
          phoneNumber: account.phoneNumber ?? undefined,
        },
      });
    }
    return this.issueTokens(account);
  }

  async login(dto: LoginDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const account = await this.prisma.account.findFirst({
      where: { email: normalizedEmail, role: dto.role },
    });
    if (
      !account ||
      !(await argon2.verify(account.passwordHash, dto.password + account.salt))
    ) {
      throw new UnauthorizedException('Invalid credentials');
    }
    if (account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }
    if (account.twoFactorEnabled && account.twoFactorSecret) {
      const challenge = await this.createTwoFactorChallenge(account.id);
      return {
        requiresTwoFactor: true,
        challengeId: challenge.id,
        expiresAt: challenge.expiresAt.toISOString(),
      };
    }
    const tokens = await this.issueTokens(account);
    return {
      requiresTwoFactor: false,
      ...tokens,
    };
  }

  async verifyTwoFactor(dto: VerifyTwoFactorDto) {
    const challenge = await this.prisma.twoFactorChallenge.findUnique({
      where: { id: dto.challengeId },
      include: { account: true },
    });
    if (
      !challenge ||
      challenge.expiresAt < new Date() ||
      challenge.resolved ||
      !challenge.account.twoFactorSecret
    ) {
      throw new UnauthorizedException('Challenge expired');
    }
    const valid = authenticator.check(
      dto.code,
      challenge.account.twoFactorSecret,
    );
    if (!valid) {
      throw new UnauthorizedException('Invalid code');
    }
    await this.prisma.twoFactorChallenge.update({
      where: { id: dto.challengeId },
      data: { resolved: true },
    });
    const tokens = await this.issueTokens(challenge.account);
    return {
      requiresTwoFactor: false,
      ...tokens,
    };
  }

  async refresh(refreshToken: string) {
    const { account } = await this.findRefreshToken(refreshToken);
    await this.revokeRefreshToken(refreshToken);
    return this.issueTokens(account);
  }

  async logout(refreshToken: string) {
    if (!refreshToken) {
      return { success: true };
    }
    await this.revokeRefreshToken(refreshToken);
    return { success: true };
  }

  async startPasswordRecovery(dto: RecoveryStartDto) {
    if (!dto.email && !dto.phoneNumber) {
      throw new BadRequestException('Email or phoneNumber is required');
    }
    const normalizedEmail = dto.email?.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : undefined;
    const account = await this.prisma.account.findFirst({
      where: {
        OR: [
          normalizedEmail ? { email: normalizedEmail } : undefined,
          normalizedPhone ? { phoneNumber: normalizedPhone } : undefined,
        ].filter(Boolean) as Array<{ email?: string; phoneNumber?: string }>,
      },
    });
    if (!account || !account.phoneNumber) {
      throw new BadRequestException('No hay cuenta con WhatsApp disponible');
    }

    await this.prisma.passwordRecovery.deleteMany({
      where: { accountId: account.id },
    });

    const code = this.generateRecoveryCode();
    const codeHash = this.hashToken(code);
    const expiresAt = new Date(Date.now() + this.recoveryCodeTtl * 1000);
    const recovery = await this.prisma.passwordRecovery.create({
      data: {
        accountId: account.id,
        codeHash,
        expiresAt,
      },
    });

    const name = account.email.split('@')[0]?.trim() || 'Paciente MeuSalud';
    await this.notifications.sendPasswordRecoveryWhatsapp({
      phoneNumber: account.phoneNumber,
      name,
      code,
      link: this.recoveryLinkBase,
      ttlSeconds: this.recoveryCodeTtl,
    });

    return {
      recoveryId: recovery.id,
      expiresAt: recovery.expiresAt.toISOString(),
    };
  }

  async verifyPasswordRecovery(dto: RecoveryVerifyDto) {
    const recovery = await this.prisma.passwordRecovery.findUnique({
      where: { id: dto.recoveryId },
      include: { account: true },
    });
    if (!recovery || recovery.expiresAt < new Date()) {
      throw new UnauthorizedException('Recovery code expired');
    }
    if (recovery.attempts >= this.recoveryMaxAttempts) {
      throw new UnauthorizedException('Recovery code locked');
    }
    const codeHash = this.hashToken(dto.code);
    if (codeHash !== recovery.codeHash) {
      await this.prisma.passwordRecovery.update({
        where: { id: recovery.id },
        data: { attempts: { increment: 1 } },
      });
      throw new UnauthorizedException('Invalid recovery code');
    }

    const resetToken = randomBytes(48).toString('hex');
    const resetTokenHash = this.hashToken(resetToken);
    const resetExpiresAt = new Date(
      Date.now() + this.recoveryResetTtl * 1000,
    );

    await this.prisma.passwordRecovery.update({
      where: { id: recovery.id },
      data: {
        resetTokenHash,
        resetExpiresAt,
        verifiedAt: new Date(),
      },
    });

    return {
      resetToken,
      resetExpiresAt: resetExpiresAt.toISOString(),
    };
  }

  async completePasswordRecovery(dto: RecoveryCompleteDto) {
    const resetTokenHash = this.hashToken(dto.resetToken);
    const recovery = await this.prisma.passwordRecovery.findFirst({
      where: { resetTokenHash },
      include: { account: true },
    });
    if (
      !recovery ||
      !recovery.resetExpiresAt ||
      recovery.resetExpiresAt < new Date() ||
      recovery.consumedAt
    ) {
      throw new UnauthorizedException('Reset token expired');
    }

    const salt = randomBytes(24).toString('hex');
    const passwordHash = await argon2.hash(dto.password + salt, {
      type: argon2.argon2id,
    });

    await this.prisma.$transaction([
      this.prisma.account.update({
        where: { id: recovery.accountId },
        data: {
          passwordHash,
          salt,
        },
      }),
      this.prisma.passwordRecovery.update({
        where: { id: recovery.id },
        data: {
          consumedAt: new Date(),
        },
      }),
      this.prisma.refreshToken.deleteMany({
        where: { accountId: recovery.accountId },
      }),
    ]);

    return { success: true };
  }

  async authorizeOAuth(dto: OAuthAuthorizeDto, authorization?: string) {
    const token = this.extractBearerToken(authorization);
    if (!token) {
      throw new UnauthorizedException('Missing access token');
    }
    const payload = verify(token, this.publicKey, {
      algorithms: ['RS256'],
    }) as { sub?: string };
    if (!payload?.sub) {
      throw new UnauthorizedException('Invalid access token');
    }
    const account = await this.prisma.account.findUnique({
      where: { id: payload.sub },
    });
    if (!account || account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }

    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId: dto.client_id },
    });
    if (!client || !client.allowedGrantTypes.includes('authorization_code')) {
      throw new UnauthorizedException('OAuth client inválido');
    }
    if (!client.redirectUris.includes(dto.redirect_uri)) {
      throw new UnauthorizedException('Redirect URI no permitido');
    }
    if (dto.code_challenge_method !== 'S256') {
      throw new BadRequestException('Unsupported code_challenge_method');
    }

    const scope = this.resolveScopes(dto.scope, client.allowedScopes);
    const code = nanoid(48);
    const codeHash = this.hashToken(code);
    const expiresAt = new Date(Date.now() + this.oauthCodeTtl * 1000);

    await this.prisma.oAuthAuthorizationCode.create({
      data: {
        codeHash,
        clientId: client.clientId,
        accountId: account.id,
        redirectUri: dto.redirect_uri,
        scope,
        codeChallenge: dto.code_challenge,
        codeChallengeMethod: dto.code_challenge_method,
        expiresAt,
      },
    });

    const redirectUrl = new URL(dto.redirect_uri);
    redirectUrl.searchParams.set('code', code);
    if (dto.state) {
      redirectUrl.searchParams.set('state', dto.state);
    }
    return redirectUrl.toString();
  }

  async exchangeOAuthToken(dto: OAuthTokenDto) {
    if (dto.grant_type === 'authorization_code') {
      return this.exchangeAuthorizationCode(dto);
    }
    if (dto.grant_type === 'client_credentials') {
      return this.exchangeClientCredentials(dto);
    }
    throw new BadRequestException('Unsupported grant_type');
  }

  getGoogleOAuthUrl(roleInput: string, redirect?: string) {
    if (!this.googleClientId || !this.googleRedirectUri) {
      throw new ServiceUnavailableException('Google OAuth no está configurado');
    }
    const role = this.parseRole(roleInput);
    const state = nanoid(48);
    const createdAt = Date.now();
    const sanitizedRedirect = this.sanitizeRedirect(redirect, this.googleSuccessRedirect);
    this.googleStateStore.set(state, { role, redirect: sanitizedRedirect, createdAt });
    const params = new URLSearchParams({
      client_id: this.googleClientId,
      redirect_uri: this.googleRedirectUri,
      response_type: 'code',
      scope: this.googleScopes,
      state,
      access_type: 'offline',
      prompt: 'consent',
    });
    return `https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`;
  }

  async handleGoogleOAuthCallback(code?: string, state?: string) {
    if (!code || !state) {
      throw new BadRequestException('Missing OAuth code or state');
    }
    const entry = this.googleStateStore.get(state);
    this.googleStateStore.delete(state);
    if (!entry) {
      throw new UnauthorizedException('OAuth state inválido');
    }
    if (Date.now() - entry.createdAt > this.googleStateTtl * 1000) {
      throw new UnauthorizedException('OAuth state expirado');
    }
    if (!this.googleClientId || !this.googleClientSecret || !this.googleRedirectUri) {
      throw new ServiceUnavailableException('Google OAuth no está configurado');
    }

    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: this.googleClientId,
        client_secret: this.googleClientSecret,
        redirect_uri: this.googleRedirectUri,
        grant_type: 'authorization_code',
      }),
    });
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      this.logger.error(`Google OAuth token error: ${errorText}`);
      return this.buildOauthErrorResult('No fue posible validar Google');
    }
    const tokenPayload = (await tokenResponse.json()) as {
      access_token?: string;
      id_token?: string;
      expires_in?: number;
      scope?: string;
      token_type?: string;
    };
    if (!tokenPayload.access_token) {
      return this.buildOauthErrorResult('Google no devolvió access token');
    }

    const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
      headers: {
        Authorization: `Bearer ${tokenPayload.access_token}`,
      },
    });
    if (!userinfoResponse.ok) {
      const errorText = await userinfoResponse.text();
      this.logger.error(`Google userinfo error: ${errorText}`);
      return this.buildOauthErrorResult('No fue posible obtener datos de Google');
    }
    const profile = (await userinfoResponse.json()) as {
      sub?: string;
      email?: string;
      email_verified?: boolean;
      name?: string;
    };

    if (!profile.email) {
      return this.buildOauthErrorResult('Google no devolvió email');
    }
    if (profile.email_verified === false) {
      return this.buildOauthErrorResult('Email de Google no verificado');
    }

    const normalizedEmail = profile.email.trim().toLowerCase();
    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing && existing.role !== entry.role) {
      throw new ConflictException('Email ya registrado con otro rol');
    }
    let account = existing;
    if (!account) {
      const salt = randomBytes(24).toString('hex');
      const passwordHash = await argon2.hash(randomBytes(32).toString('hex') + salt, {
        type: argon2.argon2id,
      });
      const doctorId =
        entry.role === AccountRole.DOCTOR ? randomUUID() : null;
      const onboardingStatus =
        entry.role === AccountRole.DOCTOR
          ? OnboardingStatus.PENDING
          : OnboardingStatus.COMPLETE;
      account = await this.prisma.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: entry.role,
          subjectId: profile.sub ?? null,
          phoneNumber: null,
          doctorId,
          onboardingStatus,
        },
      });
      if (account.role === AccountRole.DOCTOR && account.doctorId) {
        await this.rabbitmq.publishAuthEvent({
          type: 'AuthUserRegistered',
          routingKey: 'auth.user_registered',
          data: {
            authUserId: account.id,
            role: account.role,
            doctorId: account.doctorId,
            email: account.email,
            phoneNumber: account.phoneNumber ?? undefined,
          },
        });
      }
    }

    const tokens = await this.issueTokens(account);
    const redirect = entry.redirect ?? this.googleSuccessRedirect;
    if (redirect) {
      const url = new URL(redirect);
      url.searchParams.set('accessToken', tokens.accessToken);
      url.searchParams.set('refreshToken', tokens.refreshToken);
      url.searchParams.set('expiresIn', String(tokens.accessTokenExpiresIn));
      return { redirect: url.toString(), payload: null };
    }
    return { redirect: null, payload: tokens };
  }

  getAppleOAuthUrl(roleInput: string, redirect?: string) {
    if (!this.appleClientId || !this.appleRedirectUri) {
      throw new ServiceUnavailableException('Apple OAuth no está configurado');
    }
    const role = this.parseRole(roleInput);
    const state = nanoid(48);
    const createdAt = Date.now();
    const sanitizedRedirect = this.sanitizeRedirect(redirect, this.appleSuccessRedirect);
    this.appleStateStore.set(state, { role, redirect: sanitizedRedirect, createdAt });
    const params = new URLSearchParams({
      client_id: this.appleClientId,
      redirect_uri: this.appleRedirectUri,
      response_type: 'code',
      response_mode: 'form_post',
      scope: this.appleScopes,
      state,
    });
    return `https://appleid.apple.com/auth/authorize?${params.toString()}`;
  }

  async handleAppleOAuthCallback(code?: string, state?: string) {
    if (!code || !state) {
      throw new BadRequestException('Missing OAuth code or state');
    }
    const entry = this.appleStateStore.get(state);
    this.appleStateStore.delete(state);
    if (!entry) {
      throw new UnauthorizedException('OAuth state inválido');
    }
    if (Date.now() - entry.createdAt > this.appleStateTtl * 1000) {
      throw new UnauthorizedException('OAuth state expirado');
    }
    if (!this.appleClientId || !this.appleRedirectUri || !this.appleTeamId || !this.appleKeyId || !this.applePrivateKey) {
      throw new ServiceUnavailableException('Apple OAuth no está configurado');
    }

    const clientSecret = this.createAppleClientSecret();
    const tokenResponse = await fetch('https://appleid.apple.com/auth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: this.appleClientId,
        client_secret: clientSecret,
        code,
        grant_type: 'authorization_code',
        redirect_uri: this.appleRedirectUri,
      }),
    });
    if (!tokenResponse.ok) {
      const errorText = await tokenResponse.text();
      this.logger.error(`Apple OAuth token error: ${errorText}`);
      return this.buildOauthErrorResult('No fue posible validar Apple', this.appleErrorRedirect, this.appleSuccessRedirect);
    }
    const tokenPayload = (await tokenResponse.json()) as {
      access_token?: string;
      id_token?: string;
      expires_in?: number;
      token_type?: string;
    };
    if (!tokenPayload.id_token) {
      return this.buildOauthErrorResult('Apple no devolvió id_token', this.appleErrorRedirect, this.appleSuccessRedirect);
    }

    const decoded = decode(tokenPayload.id_token) as { sub?: string; email?: string; email_verified?: string };
    if (!decoded?.email) {
      return this.buildOauthErrorResult('Apple no devolvió email', this.appleErrorRedirect, this.appleSuccessRedirect);
    }
    if (decoded.email_verified && decoded.email_verified !== 'true') {
      return this.buildOauthErrorResult('Email de Apple no verificado', this.appleErrorRedirect, this.appleSuccessRedirect);
    }

    const normalizedEmail = decoded.email.trim().toLowerCase();
    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing && existing.role !== entry.role) {
      throw new ConflictException('Email ya registrado con otro rol');
    }
    let account = existing;
    if (!account) {
      const salt = randomBytes(24).toString('hex');
      const passwordHash = await argon2.hash(randomBytes(32).toString('hex') + salt, {
        type: argon2.argon2id,
      });
      const doctorId =
        entry.role === AccountRole.DOCTOR ? randomUUID() : null;
      const onboardingStatus =
        entry.role === AccountRole.DOCTOR
          ? OnboardingStatus.PENDING
          : OnboardingStatus.COMPLETE;
      account = await this.prisma.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: entry.role,
          subjectId: decoded.sub ?? null,
          phoneNumber: null,
          doctorId,
          onboardingStatus,
        },
      });
      if (account.role === AccountRole.DOCTOR && account.doctorId) {
        await this.rabbitmq.publishAuthEvent({
          type: 'AuthUserRegistered',
          routingKey: 'auth.user_registered',
          data: {
            authUserId: account.id,
            role: account.role,
            doctorId: account.doctorId,
            email: account.email,
            phoneNumber: account.phoneNumber ?? undefined,
          },
        });
      }
    }

    const tokens = await this.issueTokens(account);
    const redirect = entry.redirect ?? this.appleSuccessRedirect;
    if (redirect) {
      const url = new URL(redirect);
      url.searchParams.set('accessToken', tokens.accessToken);
      url.searchParams.set('refreshToken', tokens.refreshToken);
      url.searchParams.set('expiresIn', String(tokens.accessTokenExpiresIn));
      return { redirect: url.toString(), payload: null };
    }
    return { redirect: null, payload: tokens };
  }

  async setupTwoFactor(dto: TwoFactorSetupDto) {
    if (dto.method && dto.method !== TwoFactorMethod.TOTP) {
      throw new BadRequestException('Unsupported two-factor method');
    }
    const { account } = await this.findRefreshToken(dto.refreshToken);
    const secret = authenticator.generateSecret();
    await this.prisma.account.update({
      where: { id: account.id },
      data: {
        pendingTwoFactorSecret: secret,
      },
    });
    const issuer = this.config.get<string>('MFA_ISSUER', 'MeuSalud');
    return {
      secret,
      otpAuthUrl: authenticator.keyuri(account.email, issuer, secret),
      method: TwoFactorMethod.TOTP,
    };
  }

  async confirmTwoFactor(dto: TwoFactorCodeDto) {
    const { account } = await this.findRefreshToken(dto.refreshToken);
    if (!account.pendingTwoFactorSecret) {
      throw new BadRequestException('No pending setup');
    }
    if (!authenticator.check(dto.code, account.pendingTwoFactorSecret)) {
      throw new UnauthorizedException('Invalid code');
    }
    await this.prisma.account.update({
      where: { id: account.id },
      data: {
        twoFactorSecret: account.pendingTwoFactorSecret,
        twoFactorEnabled: true,
        pendingTwoFactorSecret: null,
      },
    });
    return { twoFactorEnabled: true };
  }

  async disableTwoFactor(dto: TwoFactorCodeDto) {
    const { account } = await this.findRefreshToken(dto.refreshToken);
    if (!account.twoFactorEnabled || !account.twoFactorSecret) {
      throw new BadRequestException('Two-factor is not enabled');
    }
    if (!authenticator.check(dto.code, account.twoFactorSecret)) {
      throw new UnauthorizedException('Invalid code');
    }
    await this.prisma.account.update({
      where: { id: account.id },
      data: {
        twoFactorEnabled: false,
        twoFactorSecret: null,
        pendingTwoFactorSecret: null,
      },
    });
    await this.prisma.twoFactorChallenge.deleteMany({
      where: { accountId: account.id },
    });
    return { twoFactorEnabled: false };
  }

  private async issueTokens(account: Account, scope?: string) {
    const payload: Record<string, unknown> = {
      sub: account.id,
      role: account.role,
      subjectId: account.subjectId,
    };
    if (account.role === AccountRole.DOCTOR) {
      if (account.doctorId) {
        payload.doctorId = account.doctorId;
      }
      payload.onboardingRequired =
        account.onboardingStatus !== OnboardingStatus.COMPLETE;
    } else {
      payload.onboardingRequired = false;
    }
    if (scope) {
      payload.scope = scope;
    }
    const signOptions: SignOptions = {
      algorithm: 'RS256',
      expiresIn: this.accessTtl,
      keyid: 'meusalud-auth',
    };
    const accessToken = sign(payload, this.privateKey, signOptions);
    const refreshToken = randomBytes(48).toString('hex');
    const refreshTokenHash = this.hashToken(refreshToken);
    const refreshExpiresAt = new Date(Date.now() + this.refreshTtl * 1000);
    await this.prisma.refreshToken.create({
      data: {
        accountId: account.id,
        tokenHash: refreshTokenHash,
        expiresAt: refreshExpiresAt,
      },
    });
    return {
      accessToken,
      accessTokenExpiresIn: this.accessTtl,
      refreshToken,
      refreshTokenExpiresAt: refreshExpiresAt.toISOString(),
      account: {
        id: account.id,
        email: account.email,
        role: account.role,
        subjectId: account.subjectId,
        doctorId: account.doctorId,
        onboardingStatus: account.onboardingStatus,
      },
    };
  }

  private async exchangeAuthorizationCode(dto: OAuthTokenDto) {
    if (!dto.code || !dto.redirect_uri || !dto.code_verifier) {
      throw new BadRequestException('Missing OAuth authorization_code parameters');
    }
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId: dto.client_id },
    });
    if (!client || !client.allowedGrantTypes.includes('authorization_code')) {
      throw new UnauthorizedException('OAuth client inválido');
    }
    if (!client.redirectUris.includes(dto.redirect_uri)) {
      throw new UnauthorizedException('Redirect URI no permitido');
    }
    if (client.secretHash && !dto.client_secret) {
      throw new UnauthorizedException('Missing client_secret');
    }
    if (client.secretHash && dto.client_secret) {
      const secretOk = await argon2.verify(client.secretHash, dto.client_secret);
      if (!secretOk) {
        throw new UnauthorizedException('Invalid client_secret');
      }
    }

    const codeHash = this.hashToken(dto.code);
    const stored = await this.prisma.oAuthAuthorizationCode.findUnique({
      where: { codeHash },
      include: { account: true },
    });
    if (!stored || stored.clientId !== client.clientId || stored.redirectUri !== dto.redirect_uri) {
      throw new UnauthorizedException('Invalid authorization code');
    }
    if (stored.expiresAt < new Date() || stored.consumedAt) {
      throw new UnauthorizedException('Authorization code expired');
    }
    if (stored.codeChallengeMethod !== 'S256') {
      throw new UnauthorizedException('Unsupported code challenge');
    }
    const challenge = this.buildPkceChallenge(dto.code_verifier);
    if (challenge !== stored.codeChallenge) {
      throw new UnauthorizedException('Invalid code_verifier');
    }

    await this.prisma.oAuthAuthorizationCode.update({
      where: { codeHash },
      data: { consumedAt: new Date() },
    });

    const tokens = await this.issueTokens(stored.account, stored.scope);
    return {
      accessToken: tokens.accessToken,
      refreshToken: tokens.refreshToken,
      token_type: 'Bearer',
      expiresIn: tokens.accessTokenExpiresIn,
      scope: stored.scope,
    };
  }

  private async exchangeClientCredentials(dto: OAuthTokenDto) {
    if (!dto.client_secret) {
      throw new BadRequestException('Missing client_secret');
    }
    const client = await this.prisma.oAuthClient.findUnique({
      where: { clientId: dto.client_id },
    });
    if (!client || !client.allowedGrantTypes.includes('client_credentials')) {
      throw new UnauthorizedException('OAuth client inválido');
    }
    if (!client.secretHash) {
      throw new UnauthorizedException('Client credentials disabled');
    }
    const secretOk = await argon2.verify(client.secretHash, dto.client_secret);
    if (!secretOk) {
      throw new UnauthorizedException('Invalid client_secret');
    }
    const scope = this.resolveScopes(dto.scope, client.allowedScopes);
    const accessToken = sign(
      {
        sub: client.clientId,
        scope,
        clientId: client.clientId,
      },
      this.privateKey,
      {
        algorithm: 'RS256',
        expiresIn: this.oauthClientTtl,
        keyid: 'meusalud-auth',
      },
    );
    return {
      accessToken,
      token_type: 'Bearer',
      expiresIn: this.oauthClientTtl,
      scope,
    };
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  private parseRole(roleInput?: string) {
    if (roleInput === AccountRole.PATIENT || roleInput === AccountRole.DOCTOR) {
      return roleInput;
    }
    throw new BadRequestException('Role inválido');
  }

  private sanitizeRedirect(redirect?: string, allowedBase?: string) {
    if (!redirect || !allowedBase) return undefined;
    if (redirect.startsWith(allowedBase)) {
      return redirect;
    }
    return undefined;
  }

  private buildOauthErrorResult(message: string, errorRedirect?: string, successRedirect?: string) {
    const redirect = errorRedirect ?? successRedirect;
    if (redirect) {
      const url = new URL(redirect);
      url.searchParams.set('error', message);
      return { redirect: url.toString(), payload: null };
    }
    throw new UnauthorizedException(message);
  }

  private extractBearerToken(authorization?: string) {
    if (!authorization) return undefined;
    const [scheme, token] = authorization.split(' ');
    if (scheme?.toLowerCase() !== 'bearer') return undefined;
    return token;
  }

  private resolveScopes(requested: string | undefined, allowed: string[]) {
    if (!requested || !requested.trim()) {
      return allowed.join(' ');
    }
    const requestedScopes = requested.split(' ').map((scope) => scope.trim()).filter(Boolean);
    const allowedSet = new Set(allowed);
    const invalid = requestedScopes.find((scope) => !allowedSet.has(scope));
    if (invalid) {
      throw new UnauthorizedException('Scope no permitido');
    }
    return requestedScopes.join(' ');
  }

  private buildPkceChallenge(verifier: string) {
    return createHash('sha256')
      .update(verifier)
      .digest('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');
  }

  private createAppleClientSecret() {
    if (!this.appleTeamId || !this.appleClientId || !this.appleKeyId || !this.applePrivateKey) {
      throw new ServiceUnavailableException('Apple OAuth no está configurado');
    }
    const now = Math.floor(Date.now() / 1000);
    return sign(
      {
        iss: this.appleTeamId,
        iat: now,
        exp: now + 600,
        aud: 'https://appleid.apple.com',
        sub: this.appleClientId,
      },
      this.applePrivateKey,
      {
        algorithm: 'ES256',
        keyid: this.appleKeyId,
      },
    );
  }

  private generateRecoveryCode() {
    return randomInt(0, 1000000).toString().padStart(6, '0');
  }

  private normalizePhoneNumber(value: string) {
    const trimmed = value.replace(/[\s.-]/g, '');
    if (!trimmed.startsWith('+')) {
      return `+${trimmed}`;
    }
    return trimmed;
  }

  private async createTwoFactorChallenge(accountId: string) {
    const id = nanoid(48);
    const expiresAt = new Date(Date.now() + this.challengeTtl * 1000);
    return this.prisma.twoFactorChallenge.create({
      data: {
        id,
        accountId,
        method: TwoFactorMethod.TOTP,
        expiresAt,
      },
    });
  }

  private async findRefreshToken(refreshToken: string) {
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token missing');
    }
    const hash = this.hashToken(refreshToken);
    const stored = await this.prisma.refreshToken.findFirst({
      where: { tokenHash: hash },
      include: { account: true },
    });
    if (!stored || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Invalid refresh token');
    }
    return stored;
  }

  private async revokeRefreshToken(refreshToken: string) {
    if (!refreshToken) {
      return;
    }
    const hash = this.hashToken(refreshToken);
    await this.prisma.refreshToken.deleteMany({ where: { tokenHash: hash } });
  }
}
