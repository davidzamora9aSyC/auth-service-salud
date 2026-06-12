import {
  BadRequestException,
  ConflictException,
  Injectable,
  Logger,
  ServiceUnavailableException,
  UnauthorizedException,
  NotFoundException,
} from '@nestjs/common';
import {
  Account,
  AccountDeletionAuditStatus,
  AccountDeletionChannel,
  AccountVerificationChannel,
  AccountRole,
  AccountStatus,
  CollaboratorStatus,
  InviteStatus,
  LoginEventSource,
  OnboardingStatus,
  Prisma,
  ProductAccessStatus,
  ProductCode,
  ProductRole,
  TwoFactorChallengePurpose,
  TwoFactorMethod,
} from '@prisma/client';
import { readFileSync } from 'node:fs';
import { createHash, createPublicKey, randomBytes, randomInt, randomUUID } from 'node:crypto';
import * as argon2 from 'argon2';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterCollaboratorDto } from './dto/register-collaborator.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { authenticator } from 'otplib';
import { decode, sign, SignOptions, verify, TokenExpiredError } from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import { TwoFactorSetupDto } from './dto/two-factor-setup.dto';
import { TwoFactorCodeDto } from './dto/two-factor-code.dto';
import { NotificationsService } from '../notifications/notifications.service';
import { RecoveryStartDto } from './dto/recovery-start.dto';
import { RecoveryVerifyDto } from './dto/recovery-verify.dto';
import { RecoveryCompleteDto } from './dto/recovery-complete.dto';
import { RecoveryLinkDto } from './dto/recovery-link.dto';
import { PasswordChangeStartDto } from './dto/password-change-start.dto';
import { PhoneChangeStartDto } from './dto/phone-change-start.dto';
import { PhoneChangeVerifyDto } from './dto/phone-change-verify.dto';
import { PhoneChangeCompleteDto } from './dto/phone-change-complete.dto';
import { PhoneAvailabilityDto } from './dto/phone-availability.dto';
import { OAuthAuthorizeDto } from './dto/oauth-authorize.dto';
import { OAuthTokenDto } from './dto/oauth-token.dto';
import { RabbitmqService } from './rabbitmq.service';
import { SimulateUserRegisteredDto } from './dto/simulate-user-registered.dto';
import { BootstrapAdminDto } from './dto/bootstrap-admin.dto';
import { AccountDeletionStartDto } from './dto/account-deletion-start.dto';
import { AccountDeletionConfirmDto } from './dto/account-deletion-confirm.dto';
import { AdminOnboardingService } from './admin-onboarding.service';
import { EmployersHttpClient } from './employers-http.client';
import { CreateEmployerInviteAccountDto } from './dto/create-employer-invite-account.dto';
import { CreatePatientInviteAccountDto } from './dto/create-patient-invite-account.dto';
import { LinkPatientAffiliateInviteDto } from './dto/link-patient-affiliate-invite.dto';
import { GrantEmployerAccessDto } from './dto/grant-employer-access.dto';
import { RegisterMeuredDto } from './dto/register-meured.dto';
import { SelectProductAccessDto } from './dto/select-product-access.dto';

type RequestMeta = {
  ip?: string;
  forwardedFor?: string;
  userAgent?: string;
};

type DeletionOperationLog = {
  service: string;
  ok: boolean;
  operations?: Record<string, number>;
  error?: string;
};

type ProductAccessContext = {
  id: string;
  product: ProductCode;
  role: ProductRole;
  subjectId?: string | null;
  status: ProductAccessStatus;
};

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
  private readonly accountDeletionCodeTtl: number;
  private readonly accountDeletionMaxAttempts: number;
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
  private readonly appleClientId?: string;
  private readonly appleTeamId?: string;
  private readonly appleKeyId?: string;
  private readonly appleRedirectUri?: string;
  private readonly appleScopes: string;
  private readonly appleStateTtl: number;
  private readonly appleSuccessRedirect?: string;
  private readonly appleErrorRedirect?: string;
  private readonly applePrivateKey?: string;
  private readonly usersBaseUrl: string;
  private readonly doctorsBaseUrl: string;
  private readonly clinicsInternalBaseUrl: string;
  private readonly tokenDebug: boolean;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly notifications: NotificationsService,
    private readonly rabbitmq: RabbitmqService,
    private readonly adminOnboarding: AdminOnboardingService,
    private readonly employersHttp: EmployersHttpClient,
  ) {
    const inlinePrivateKey = this.config.get<string>('JWT_PRIVATE_KEY');
    if (inlinePrivateKey?.trim()) {
      this.privateKey = Buffer.from(
        inlinePrivateKey.replace(/\\n/g, '\n'),
        'utf-8',
      );
    } else {
      const privateKeyPath = this.config.get<string>('JWT_PRIVATE_KEY_PATH');
      if (!privateKeyPath) {
        throw new Error(
          'JWT_PRIVATE_KEY or JWT_PRIVATE_KEY_PATH is required',
        );
      }
      this.privateKey = readFileSync(privateKeyPath);
    }
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
    this.tokenDebug = this.config.get<string>('AUTH_DEBUG_TOKENS') === 'true';
    this.accountDeletionCodeTtl = parseInt(
      this.config.get<string>('ACCOUNT_DELETION_CODE_TTL', `${this.recoveryCodeTtl}`),
      10,
    );
    this.accountDeletionMaxAttempts = parseInt(
      this.config.get<string>('ACCOUNT_DELETION_MAX_ATTEMPTS', `${this.recoveryMaxAttempts}`),
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
    this.usersBaseUrl =
      this.config.get<string>('USERS_BASE_URL') ??
      'http://users-service:3008/usersms';
    this.doctorsBaseUrl =
      this.config.get<string>('DOCTORS_BASE_URL') ??
      'http://doctors-service:3009/doctorsms';
    this.clinicsInternalBaseUrl =
      this.config.get<string>('CLINICS_INTERNAL_BASE_URL') ??
      'http://clinics-service:3025/clinicsms';
    const appleKeyPath = this.config.get<string>('APPLE_PRIVATE_KEY_PATH');
    if (appleKeyPath) {
      this.applePrivateKey = readFileSync(appleKeyPath, 'utf-8');
    } else {
      const inlineKey = this.config.get<string>('APPLE_PRIVATE_KEY');
      this.applePrivateKey = inlineKey?.replace(/\\n/g, '\n');
    }
  }

  async register(dto: RegisterDto) {
    if (dto.role === AccountRole.COLLABORATOR) {
      throw new BadRequestException('Use el flujo de invitacion de colaborador');
    }
    if (dto.role === AccountRole.ADMIN) {
      throw new BadRequestException('No esta permitido registrar cuentas ADMIN por este endpoint');
    }
    if (dto.role === AccountRole.COMERCIAL) {
      throw new BadRequestException('No esta permitido registrar cuentas COMERCIAL por este endpoint');
    }
    if (dto.role === AccountRole.MEMBER) {
      throw new BadRequestException('Use el flujo de registro de MeuRed');
    }
      const inviteToken = dto.inviteToken?.trim();
      if (inviteToken && dto.role === AccountRole.EMPLOYER) {
        throw new BadRequestException(
          'Para unirte a una empresa existente usa el enlace de invitacion del portal empresa',
        );
      }
      if (inviteToken && dto.role !== AccountRole.DOCTOR) {
        throw new BadRequestException('inviteToken solo aplica para registro de medicos');
      }
      const normalizedEmail = dto.email.trim().toLowerCase();
      const normalizedPhone = this.normalizePhoneNumber(dto.phoneNumber);
      let invite: { doctorId: string } | null = null;
      if (inviteToken && dto.role === AccountRole.DOCTOR) {
        try {
          invite = await this.adminOnboarding.resolveInviteForRegister(inviteToken, normalizedEmail);
        } catch (error) {
          if (!(error instanceof NotFoundException)) {
            throw error;
          }
        }
      }
      const isAdminInvite = Boolean(invite);
    const firstName = dto.firstName?.trim() || undefined;
    const lastName = dto.lastName?.trim() || undefined;
    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      // Si el email ya existe y la contraseña coincide, intentamos agregar el nuevo rol
      const passwordOk = await argon2.verify(existing.passwordHash, dto.password + existing.salt);
      if (!passwordOk) {
        throw new ConflictException('El email ya esta registrado');
      }
      return this.addRoleToAccount(existing, dto, firstName, lastName, inviteToken, invite?.doctorId, isAdminInvite);
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
        dto.role === AccountRole.DOCTOR ? (invite?.doctorId ?? randomUUID()) : null;
      const employerId = dto.role === AccountRole.EMPLOYER ? randomUUID() : null;
    const onboardingStatus =
      dto.role === AccountRole.DOCTOR ||
      dto.role === AccountRole.CLINIC ||
      dto.role === AccountRole.EMPLOYER
        ? OnboardingStatus.PENDING
        : OnboardingStatus.COMPLETE;

    if (dto.role === AccountRole.EMPLOYER) {
      const companyName = dto.companyName?.trim();
      const taxId = dto.taxId?.trim();
      if (!companyName || !taxId) {
        throw new BadRequestException(
          'Datos de empresa requeridos para registrar una nueva organizacion',
        );
      }
      await this.employersHttp.prepareFounder({
        employerId: employerId!,
        displayName: companyName,
        taxId,
        email: normalizedEmail,
        phoneNumber: normalizedPhone,
      });
    }

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
          employerId,
          onboardingStatus,
        },
      });
    } catch (error) {
      if (employerId) {
        await this.employersHttp.rollbackFounder(employerId).catch(() => undefined);
      }
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

    if (dto.role === AccountRole.EMPLOYER && employerId) {
      try {
        await this.ensureLegacyProductAccess(account);
        await this.employersHttp.finalizeFounder({
          employerId,
          authUserId: account.id,
        });
      } catch (error) {
        await this.prisma.account.delete({ where: { id: account.id } }).catch(() => undefined);
        await this.employersHttp.rollbackFounder(employerId).catch(() => undefined);
        throw error;
      }
    }
      if (account.role === AccountRole.DOCTOR && inviteToken && !isAdminInvite) {
        try {
          await this.completeClinicDoctorInviteRegistration(account, inviteToken);
        } catch (error) {
          await this.prisma.account.delete({ where: { id: account.id } }).catch(() => undefined);
          throw error;
        }
      }
    if (account.role === AccountRole.PATIENT) {
      if (!firstName || !lastName) {
        await this.prisma.account.delete({ where: { id: account.id } });
        throw new BadRequestException('Nombre y apellido son requeridos');
      }
      try {
        const patientId = await this.linkOrCreatePatientForAccount(account, firstName, lastName);
        account = await this.prisma.account.update({
          where: { id: account.id },
          data: { subjectId: patientId },
        });
      } catch (error) {
        await this.prisma.account.delete({ where: { id: account.id } }).catch(() => undefined);
        throw error;
      }
    }
      await this.publishUserRegisteredEvent(account, {
        firstName,
        lastName,
        companyName: dto.companyName,
        taxId: dto.taxId,
      });
      if (inviteToken && invite) {
        await this.adminOnboarding.markInviteAccepted(inviteToken, account.id);
      }
    await this.ensureLegacyProductAccess(account);
    await this.recordIdentityReuse(account, normalizedEmail, normalizedPhone);
    const tokens = await this.issueTokens(account);
    const availableProductAccess = await this.getAvailableProductAccess(account.id);
    return { ...tokens, availableProductAccess };
  }

  async registerMeured(dto: RegisterMeuredDto) {
    if (
      dto.role !== ProductRole.DOCTOR &&
      dto.role !== ProductRole.RESEARCHER &&
      dto.role !== ProductRole.STUDENT &&
      dto.role !== ProductRole.MEDICAL_ENTITY
    ) {
      throw new BadRequestException('Rol MeuRed no soportado');
    }

    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber ? this.normalizePhoneNumber(dto.phoneNumber) : null;
    let account = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });

    if (account) {
      if (!(await argon2.verify(account.passwordHash, dto.password + account.salt))) {
        throw new ConflictException('El email ya esta registrado');
      }
      if (account.status !== AccountStatus.ACTIVE) {
        throw new UnauthorizedException('Account disabled');
      }
      if (normalizedPhone && account.phoneNumber && account.phoneNumber !== normalizedPhone) {
        throw new ConflictException('El telefono no coincide con la cuenta existente');
      }
      if (normalizedPhone && !account.phoneNumber) {
        account = await this.prisma.account.update({
          where: { id: account.id },
          data: { phoneNumber: normalizedPhone },
        });
      }
    } else {
      if (!normalizedPhone) {
        throw new BadRequestException('El telefono es obligatorio para crear una cuenta MeuRed');
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
      account = await this.prisma.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: AccountRole.MEMBER,
          subjectId: null,
          phoneNumber: normalizedPhone,
          doctorId: null,
          onboardingStatus: OnboardingStatus.COMPLETE,
        },
      });
      await this.recordIdentityReuse(account, normalizedEmail, normalizedPhone);
    }

    const productAccess = await this.prisma.accountProductAccess.upsert({
      where: {
        accountId_product_role: {
          accountId: account.id,
          product: ProductCode.MEURED,
          role: dto.role,
        },
      },
      create: {
        accountId: account.id,
        product: ProductCode.MEURED,
        role: dto.role,
        subjectId: randomUUID(),
        status: ProductAccessStatus.ACTIVE,
      },
      update: {
        status: ProductAccessStatus.ACTIVE,
      },
    });

    const availableProductAccess = await this.getAvailableProductAccess(account.id);
    if (account.twoFactorEnabled) {
      return this.buildTwoFactorRequiredResponse(account, {
        sessionRole: account.role,
        availableProductAccess,
      });
    }

    const tokens = await this.issueTokens(account, {
      sessionRole: account.role,
      productAccess,
    });
    return {
      requiresTwoFactor: false as const,
      ...tokens,
      availableProductAccess,
    };
  }

  private async addRoleToAccount(
    account: Account,
    dto: RegisterDto,
    firstName?: string,
    lastName?: string,
    inviteToken?: string,
    inviteDoctorId?: string | null,
    isAdminInvite?: boolean,
  ) {
    if (account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }
    // Verificar que el rol no esté ya registrado
    const isPrimaryRole = account.role === dto.role;
    if (isPrimaryRole) {
      throw new ConflictException('Ya tienes una cuenta con este rol');
    }
    const existingProfile = await this.prisma.accountRoleProfile.findUnique({
      where: { accountId_role: { accountId: account.id, role: dto.role } },
    });
    if (existingProfile) {
      throw new ConflictException('Ya tienes una cuenta con este rol');
    }

    if (dto.role === AccountRole.PATIENT) {
      if (!firstName || !lastName) {
        throw new BadRequestException('Nombre y apellido son requeridos');
      }
      const patientId = await this.linkOrCreatePatientForAccount(account, firstName, lastName);
      await this.prisma.accountRoleProfile.create({
        data: {
          accountId: account.id,
          role: AccountRole.PATIENT,
          subjectId: patientId,
          onboardingStatus: OnboardingStatus.COMPLETE,
        },
      });
    } else if (dto.role === AccountRole.DOCTOR) {
      if (isAdminInvite && !inviteDoctorId) {
        throw new BadRequestException('Invitacion invalida');
      }
      const doctorId = inviteDoctorId ?? randomUUID();
      await this.prisma.accountRoleProfile.create({
        data: {
          accountId: account.id,
          role: AccountRole.DOCTOR,
          doctorId,
          onboardingStatus: OnboardingStatus.PENDING,
        },
      });
      // Guardar doctorId en Account para compatibilidad con issueTokens
      if (!account.doctorId) {
        await this.prisma.account.update({
          where: { id: account.id },
          data: { doctorId },
        });
        account = { ...account, doctorId };
      }
      if (inviteToken && !isAdminInvite) {
        await this.completeClinicDoctorInviteRegistration({ ...account }, inviteToken);
      }
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_PRO, ProductRole.DOCTOR, doctorId);
    } else if (dto.role === AccountRole.CLINIC) {
      await this.prisma.accountRoleProfile.create({
        data: {
          accountId: account.id,
          role: AccountRole.CLINIC,
          onboardingStatus: OnboardingStatus.PENDING,
        },
      });
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_PRO, ProductRole.MEDICAL_ENTITY, null);
    } else if (dto.role === AccountRole.EMPLOYER) {
      if (!dto.companyName?.trim() || !dto.taxId?.trim()) {
        throw new BadRequestException(
          'Datos de empresa requeridos para registrar una nueva organizacion',
        );
      }
      if (account.employerId) {
        throw new ConflictException('Esta cuenta ya administra una empresa');
      }
      const existingEmployerProfile = await this.prisma.accountRoleProfile.findUnique({
        where: { accountId_role: { accountId: account.id, role: AccountRole.EMPLOYER } },
      });
      if (existingEmployerProfile?.subjectId) {
        throw new ConflictException('Esta cuenta ya pertenece a un portal de empresa');
      }
      const employerId = randomUUID();
      await this.employersHttp.prepareFounder({
        employerId,
        displayName: dto.companyName.trim(),
        taxId: dto.taxId.trim(),
        email: account.email,
        phoneNumber: account.phoneNumber ?? undefined,
      });
      try {
        await this.prisma.accountRoleProfile.create({
          data: {
            accountId: account.id,
            role: AccountRole.EMPLOYER,
            subjectId: employerId,
            onboardingStatus: OnboardingStatus.PENDING,
          },
        });
        await this.prisma.account.update({
          where: { id: account.id },
          data: { employerId },
        });
        account = { ...account, employerId };
        await this.ensureProductAccess(
          account.id,
          ProductCode.MEUDOC_EMPLOYER,
          ProductRole.EMPLOYER_ADMIN,
          employerId,
        );
        await this.employersHttp.finalizeFounder({
          employerId,
          authUserId: account.id,
        });
        await this.publishUserRegisteredEvent(account, {
          firstName,
          lastName,
          companyName: dto.companyName,
          taxId: dto.taxId,
        });
      } catch (error) {
        await this.employersHttp.rollbackFounder(employerId).catch(() => undefined);
        throw error;
      }
    } else {
      throw new BadRequestException('Rol no soportado para registro multi-rol');
    }

    const updatedAccount = await this.prisma.account.findUniqueOrThrow({
      where: { id: account.id },
    });
    const availableRoles = await this.getAvailableRoles(updatedAccount);
    const availableProductAccess = await this.getAvailableProductAccess(updatedAccount.id);
    if (updatedAccount.twoFactorEnabled) {
      return this.buildTwoFactorRequiredResponse(updatedAccount, {
        sessionRole: dto.role,
        availableRoles,
        availableProductAccess,
      });
    }

    const tokens = await this.issueTokens(updatedAccount, { sessionRole: dto.role });
    return { ...tokens, availableRoles, availableProductAccess };
  }

  async login(dto: LoginDto, meta?: RequestMeta) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const account = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
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
    const sessionRole = await this.resolveSessionRole(account, dto.role);
    if (sessionRole === AccountRole.DOCTOR && !account.doctorId) {
      throw new BadRequestException('No hay perfil de doctor para esta cuenta');
    }
    if (sessionRole === AccountRole.EMPLOYER && !account.employerId) {
      const employerProfile = await this.prisma.accountRoleProfile.findUnique({
        where: { accountId_role: { accountId: account.id, role: AccountRole.EMPLOYER } },
      });
      if (!employerProfile?.subjectId) {
        throw new BadRequestException('No hay perfil de empresa para esta cuenta');
      }
    }
    const availableRoles = await this.getAvailableRoles(account);
    if (account.twoFactorEnabled) {
      return this.buildTwoFactorRequiredResponse(account, {
        sessionRole,
        availableRoles,
      });
    }
    const tokens = await this.issueTokens(account, { sessionRole });
    await this.recordLoginHistory(account, sessionRole, LoginEventSource.PASSWORD, meta);
    const availableProductAccess = await this.getAvailableProductAccess(account.id);
    return {
      requiresTwoFactor: false,
      ...tokens,
      availableRoles,
      availableProductAccess,
    };
  }

  async selectRole(refreshToken: string, role: AccountRole) {
    const tokenHash = this.hashToken(refreshToken);
    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { account: true },
    });
    if (!stored || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token inválido o expirado');
    }
    if (stored.account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }
    const sessionRole = await this.resolveSessionRole(stored.account, role);
    await this.prisma.refreshToken.delete({ where: { tokenHash } });
    const tokens = await this.issueTokens(stored.account, { sessionRole });
    const availableRoles = await this.getAvailableRoles(stored.account);
    const availableProductAccess = await this.getAvailableProductAccess(stored.account.id);
    return { requiresTwoFactor: false as const, ...tokens, availableRoles, availableProductAccess };
  }

  async listProductAccess(authUserId: string) {
    return this.getAvailableProductAccess(authUserId);
  }

  async selectProductAccess(dto: SelectProductAccessDto) {
    const tokenHash = this.hashToken(dto.refreshToken);
    const stored = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      include: { account: true },
    });
    if (!stored || stored.expiresAt < new Date()) {
      throw new UnauthorizedException('Refresh token invalido o expirado');
    }
    if (stored.account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }

    const productAccess = await this.prisma.accountProductAccess.findFirst({
      where: {
        accountId: stored.account.id,
        product: dto.product,
        role: dto.role,
        ...(dto.accessId ? { id: dto.accessId } : {}),
      },
    });
    if (!productAccess || productAccess.status === ProductAccessStatus.DISABLED) {
      throw new BadRequestException('Acceso de producto no disponible');
    }

    await this.prisma.refreshToken.delete({ where: { tokenHash } });
    const tokens = await this.issueTokens(stored.account, {
      sessionRole: stored.account.role,
      productAccess,
    });
    const availableProductAccess = await this.getAvailableProductAccess(stored.account.id);
    return {
      requiresTwoFactor: false as const,
      ...tokens,
      availableProductAccess,
    };
  }

  async registerCollaborator(dto: RegisterCollaboratorDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : null;
    const tokenHash = this.hashToken(dto.inviteToken);
    const invite = await this.prisma.collaboratorInvite.findUnique({
      where: { tokenHash },
      include: {
        permissions: { include: { permission: true } },
        agendas: true,
      },
    });
    if (!invite || invite.status !== InviteStatus.PENDING) {
      throw new BadRequestException('Invitacion invalida');
    }
    if (invite.expiresAt < new Date()) {
      await this.prisma.collaboratorInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.EXPIRED },
      });
      throw new BadRequestException('Invitacion expirada');
    }
    if (invite.email !== normalizedEmail) {
      throw new BadRequestException('El email no coincide con la invitacion');
    }
    if (invite.phoneNumber && normalizedPhone && invite.phoneNumber !== normalizedPhone) {
      throw new BadRequestException('El telefono no coincide con la invitacion');
    }

    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      if (existing.status !== AccountStatus.ACTIVE) {
        throw new UnauthorizedException('Account disabled');
      }
      const validPassword = await argon2.verify(
        existing.passwordHash,
        dto.password + existing.salt,
      );
      if (!validPassword) {
        throw new UnauthorizedException('Invalid credentials');
      }
      if (existing.role === AccountRole.DOCTOR) {
        throw new ConflictException(
          'El email ya esta registrado como doctor y no puede aceptar invitaciones de colaborador',
        );
      }
      if (existing.role !== AccountRole.COLLABORATOR && existing.role !== AccountRole.PATIENT) {
        throw new ConflictException('El email ya esta registrado con otro tipo de cuenta');
      }
      const linkedCollaborator = await this.prisma.collaborator.findUnique({
        where: { accountId: existing.id },
        select: { id: true },
      });
      if (linkedCollaborator) {
        throw new ConflictException(
          'La cuenta ya tiene una relacion de colaborador activa',
        );
      }
    }

    const account = await this.prisma.$transaction(async (tx) => {
      const accountRecord = existing
        ? await tx.account.update({
            where: { id: existing.id },
            data: {
              phoneNumber: normalizedPhone ?? existing.phoneNumber ?? null,
            },
          })
        : await (async () => {
            const salt = randomBytes(24).toString('hex');
            const passwordHash = await argon2.hash(dto.password + salt, {
              type: argon2.argon2id,
            });
            return tx.account.create({
              data: {
                email: normalizedEmail,
                passwordHash,
                salt,
                role: AccountRole.COLLABORATOR,
                subjectId: null,
                phoneNumber: normalizedPhone,
                onboardingStatus: OnboardingStatus.COMPLETE,
              },
            });
          })();
      const collaborator = await tx.collaborator.create({
        data: {
          accountId: accountRecord.id,
          doctorId: invite.doctorId,
          firstName: dto.firstName,
          lastName: dto.lastName,
        },
      });
      const permissionIds = invite.permissions.map(
        (entry) => entry.permissionId,
      );
      if (permissionIds.length > 0) {
        await tx.collaboratorPermission.createMany({
          data: permissionIds.map((permissionId) => ({
            collaboratorId: collaborator.id,
            permissionId,
          })),
        });
      }
      const agendaIds = invite.agendas.map((agenda) => agenda.agendaId);
      if (agendaIds.length > 0) {
        await tx.collaboratorAgenda.createMany({
          data: agendaIds.map((agendaId) => ({
            collaboratorId: collaborator.id,
            agendaId,
          })),
        });
      }
      await tx.collaboratorInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.ACCEPTED },
      });

      if (existing?.role === AccountRole.PATIENT) {
        await tx.accountRoleProfile.upsert({
          where: {
            accountId_role: {
              accountId: accountRecord.id,
              role: AccountRole.COLLABORATOR,
            },
          },
          update: {
            subjectId: null,
            onboardingStatus: OnboardingStatus.COMPLETE,
          },
          create: {
            accountId: accountRecord.id,
            role: AccountRole.COLLABORATOR,
            subjectId: null,
            onboardingStatus: OnboardingStatus.COMPLETE,
          },
        });
      }
      return accountRecord;
    });

    if (account.twoFactorEnabled) {
      return this.buildTwoFactorRequiredResponse(account, {
        sessionRole: AccountRole.COLLABORATOR,
        availableRoles: await this.getAvailableRoles(account),
      });
    }
    return this.issueTokens(account, { sessionRole: AccountRole.COLLABORATOR });
  }

  async createEmployerInviteAccount(dto: CreateEmployerInviteAccountDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : null;

    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      if (existing.status !== AccountStatus.ACTIVE) {
        throw new UnauthorizedException('Account disabled');
      }
      const validPassword = await argon2.verify(
        existing.passwordHash,
        dto.password + existing.salt,
      );
      if (!validPassword) {
        throw new UnauthorizedException('Invalid credentials');
      }
      const employerProfile = await this.prisma.accountRoleProfile.findUnique({
        where: {
          accountId_role: { accountId: existing.id, role: AccountRole.EMPLOYER },
        },
      });
      if (employerProfile?.subjectId) {
        throw new ConflictException('Esta cuenta ya pertenece a un portal de empresa');
      }
      if (existing.employerId) {
        throw new ConflictException('Esta cuenta ya administra una empresa');
      }

      if (normalizedPhone) {
        const existingPhone = await this.prisma.account.findUnique({
          where: { phoneNumber: normalizedPhone },
          select: { id: true },
        });
        if (existingPhone && existingPhone.id !== existing.id) {
          throw new ConflictException('El numero de telefono ya esta registrado');
        }
      }

      const account = await this.prisma.account.update({
        where: { id: existing.id },
        data: {
          phoneNumber: normalizedPhone ?? existing.phoneNumber ?? null,
          onboardingStatus: OnboardingStatus.COMPLETE,
        },
      });
      return { accountId: account.id, email: account.email, created: false };
    }

    if (normalizedPhone) {
      const existingPhone = await this.prisma.account.findUnique({
        where: { phoneNumber: normalizedPhone },
      });
      if (existingPhone) {
        throw new ConflictException('El numero de telefono ya esta registrado');
      }
    }

    const salt = randomBytes(24).toString('hex');
    const passwordHash = await argon2.hash(dto.password + salt, {
      type: argon2.argon2id,
    });

    const account = await this.prisma.account.create({
      data: {
        email: normalizedEmail,
        passwordHash,
        salt,
        role: AccountRole.EMPLOYER,
        phoneNumber: normalizedPhone,
        employerId: null,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
    });

    await this.recordIdentityReuse(account, normalizedEmail, normalizedPhone ?? '');
    return { accountId: account.id, email: account.email, created: true };
  }

  async verifyOrCreateEmployerMemberForInvite(dto: CreateEmployerInviteAccountDto) {
    const result = await this.createEmployerInviteAccount(dto);
    return { authUserId: result.accountId, created: result.created };
  }

  async verifyOrCreatePatientForInvite(dto: CreatePatientInviteAccountDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber ? this.normalizePhoneNumber(dto.phoneNumber) : null;

    const account = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.account.findUnique({ where: { email: normalizedEmail } });
      if (existing) {
        if (existing.status !== AccountStatus.ACTIVE) {
          throw new UnauthorizedException('Account disabled');
        }
        const validPassword = await argon2.verify(existing.passwordHash, dto.password + existing.salt);
        if (!validPassword) {
          throw new ConflictException(
            'Ya existe una cuenta con este correo. Usa la contraseña de esa cuenta (no es un registro nuevo) o restablécela desde iniciar sesión.',
          );
        }

        if (normalizedPhone) {
          const existingPhone = await tx.account.findUnique({
            where: { phoneNumber: normalizedPhone },
            select: { id: true },
          });
          if (existingPhone && existingPhone.id !== existing.id) {
            throw new ConflictException(
              'El número de teléfono ya está registrado en otra cuenta. Pide a tu empresa reenviar la invitación con otro celular.',
            );
          }
        }

        return tx.account.update({
          where: { id: existing.id },
          data: {
            phoneNumber: normalizedPhone ?? existing.phoneNumber ?? null,
            onboardingStatus: OnboardingStatus.COMPLETE,
          },
        });
      }

      if (normalizedPhone) {
        const existingPhone = await tx.account.findUnique({
          where: { phoneNumber: normalizedPhone },
        });
        if (existingPhone) {
          throw new ConflictException(
            'El número de teléfono ya está registrado en otra cuenta. Pide a tu empresa reenviar la invitación con otro celular.',
          );
        }
      }

      const salt = randomBytes(24).toString('hex');
      const passwordHash = await argon2.hash(dto.password + salt, { type: argon2.argon2id });
      const created = await tx.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: AccountRole.PATIENT,
          phoneNumber: normalizedPhone,
          employerId: null,
          onboardingStatus: OnboardingStatus.COMPLETE,
        },
      });
      await this.recordIdentityReuse(created, normalizedEmail, normalizedPhone ?? '');
      return created;
    });

    const patientId = await this.linkOrCreatePatientForAccount(account, dto.firstName.trim(), dto.lastName.trim());

    await this.prisma.accountRoleProfile.upsert({
      where: {
        accountId_role: {
          accountId: account.id,
          role: AccountRole.PATIENT,
        },
      },
      update: {
        subjectId: patientId,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
      create: {
        accountId: account.id,
        role: AccountRole.PATIENT,
        subjectId: patientId,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
    });

    return { authUserId: account.id, patientId };
  }

  async accountExistsByEmail(email: string) {
    const normalizedEmail = email.trim().toLowerCase();
    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
      select: { id: true, status: true },
    });
    return { exists: Boolean(existing && existing.status === AccountStatus.ACTIVE) };
  }

  /**
   * Vincula perfil paciente a una cuenta ya existente (invitación empleado afiliado validada en employers-service).
   * No pide contraseña: la posesión del token de invitación + email de la invitación es la autorización.
   */
  async linkPatientForAffiliateInvite(dto: LinkPatientAffiliateInviteDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber ? this.normalizePhoneNumber(dto.phoneNumber) : null;

    const existing = await this.prisma.account.findUnique({ where: { email: normalizedEmail } });
    if (!existing) {
      throw new NotFoundException('No existe una cuenta con este correo');
    }
    if (existing.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }

    if (normalizedPhone) {
      const existingPhone = await this.prisma.account.findUnique({
        where: { phoneNumber: normalizedPhone },
        select: { id: true },
      });
      if (existingPhone && existingPhone.id !== existing.id) {
        throw new ConflictException(
          'El número de teléfono ya está registrado en otra cuenta. Pide a tu empresa reenviar la invitación con otro celular.',
        );
      }
    }

    const account = await this.prisma.account.update({
      where: { id: existing.id },
      data: {
        phoneNumber: normalizedPhone ?? existing.phoneNumber ?? null,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
    });

    const patientId = await this.resolvePatientForAffiliateInvite(
      account,
      dto.firstName.trim(),
      dto.lastName.trim(),
    );

    await this.prisma.accountRoleProfile.upsert({
      where: {
        accountId_role: {
          accountId: account.id,
          role: AccountRole.PATIENT,
        },
      },
      update: {
        subjectId: patientId,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
      create: {
        accountId: account.id,
        role: AccountRole.PATIENT,
        subjectId: patientId,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
    });

    return { authUserId: account.id, patientId };
  }

  async grantEmployerAccess(dto: GrantEmployerAccessDto) {
    const account = await this.prisma.account.findUnique({
      where: { id: dto.accountId },
    });
    if (!account) {
      throw new NotFoundException('Cuenta no encontrada');
    }
    if (account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Account disabled');
    }

    await this.prisma.accountRoleProfile.upsert({
      where: {
        accountId_role: {
          accountId: dto.accountId,
          role: AccountRole.EMPLOYER,
        },
      },
      create: {
        accountId: dto.accountId,
        role: AccountRole.EMPLOYER,
        subjectId: dto.employerId,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
      update: {
        subjectId: dto.employerId,
        onboardingStatus: OnboardingStatus.COMPLETE,
      },
    });

    await this.ensureProductAccess(
      dto.accountId,
      ProductCode.MEUDOC_EMPLOYER,
      dto.productRole,
      dto.employerId,
    );

    return {
      accountId: dto.accountId,
      employerId: dto.employerId,
      productRole: dto.productRole,
    };
  }

  async publishUserRegisteredTestEvent(dto: SimulateUserRegisteredDto) {
    if (
      dto.role !== AccountRole.PATIENT &&
      dto.role !== AccountRole.DOCTOR &&
      dto.role !== AccountRole.CLINIC
    ) {
      throw new BadRequestException('Role invalido para simulacion');
    }

    const authUserId = dto.authUserId?.trim() || randomUUID();
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : undefined;
    const firstName = dto.firstName?.trim() || undefined;
    const lastName = dto.lastName?.trim() || undefined;
    const doctorId =
      dto.role === AccountRole.DOCTOR
        ? dto.doctorId?.trim() || randomUUID()
        : undefined;

    await this.rabbitmq.publishAuthEvent({
      type: 'AuthUserRegistered',
      routingKey: 'auth.user_registered',
      data: {
        authUserId,
        role: dto.role,
        doctorId,
        email: normalizedEmail,
        phoneNumber: normalizedPhone,
        firstName,
        lastName,
      },
    });

    return {
      published: true,
      exchange: this.config.get<string>('RABBITMQ_EXCHANGE_AUTH') ?? 'auth.events',
      routingKey: 'auth.user_registered',
      data: {
        authUserId,
        role: dto.role,
        doctorId,
        email: normalizedEmail,
        phoneNumber: normalizedPhone,
        firstName,
        lastName,
      },
    };
  }

  async bootstrapAdmin(dto: BootstrapAdminDto, bootstrapToken?: string) {
    const expectedToken = this.config.get<string>('ADMIN_BOOTSTRAP_TOKEN');
    if (!expectedToken) {
      throw new ServiceUnavailableException('Bootstrap de admin deshabilitado');
    }
    if (!bootstrapToken || bootstrapToken !== expectedToken) {
      throw new UnauthorizedException('Token de bootstrap invalido');
    }

    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : null;

    const existingByEmail = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existingByEmail) {
      throw new ConflictException('El email ya esta registrado');
    }
    if (normalizedPhone) {
      const existingByPhone = await this.prisma.account.findUnique({
        where: { phoneNumber: normalizedPhone },
      });
      if (existingByPhone) {
        throw new ConflictException('El numero de telefono ya esta registrado');
      }
    }

    const salt = randomBytes(24).toString('hex');
    const passwordHash = await argon2.hash(dto.password + salt, {
      type: argon2.argon2id,
    });

    let account: Account;
    try {
      account = await this.prisma.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: AccountRole.ADMIN,
          subjectId: null,
          phoneNumber: normalizedPhone,
          doctorId: null,
          onboardingStatus: OnboardingStatus.COMPLETE,
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
      }
      throw error;
    }

    return this.issueTokens(account);
  }

  async adminCreateCommercialAccount(dto: {
    email: string;
    password: string;
    phoneNumber?: string;
  }) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : null;

    const existingByEmail = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existingByEmail) {
      throw new ConflictException('El email ya esta registrado');
    }
    if (normalizedPhone) {
      const existingByPhone = await this.prisma.account.findUnique({
        where: { phoneNumber: normalizedPhone },
      });
      if (existingByPhone) {
        throw new ConflictException('El numero de telefono ya esta registrado');
      }
    }

    const salt = randomBytes(24).toString('hex');
    const passwordHash = await argon2.hash(dto.password + salt, {
      type: argon2.argon2id,
    });

    let account: Account;
    try {
      account = await this.prisma.account.create({
        data: {
          email: normalizedEmail,
          passwordHash,
          salt,
          role: AccountRole.COMERCIAL,
          subjectId: null,
          phoneNumber: normalizedPhone,
          doctorId: null,
          onboardingStatus: OnboardingStatus.COMPLETE,
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
      }
      throw error;
    }

    await this.ensureProductAccess(
      account.id,
      ProductCode.MEUDOC_ADMIN,
      ProductRole.COMERCIAL,
      null,
    );

    return {
      id: account.id,
      email: account.email,
      phoneNumber: account.phoneNumber,
      role: account.role,
      status: account.status,
      createdAt: account.createdAt.toISOString(),
    };
  }

  async adminListCommercialAccounts(query: { page?: number; limit?: number; q?: string }) {
    return this.adminListAccounts({
      ...query,
      role: AccountRole.COMERCIAL,
    });
  }

  async verifyTwoFactor(dto: VerifyTwoFactorDto, meta?: RequestMeta) {
    const challenge = await this.prisma.twoFactorChallenge.findUnique({
      where: { id: dto.challengeId },
      include: { account: true },
    });
    if (
      !challenge ||
      challenge.expiresAt < new Date() ||
      challenge.resolved ||
      challenge.purpose !== TwoFactorChallengePurpose.LOGIN
    ) {
      throw new UnauthorizedException('Challenge expired');
    }
    const method = challenge.method ?? this.resolveTwoFactorMethod(challenge.account);
    const secret = challenge.account.twoFactorSecret;
    let valid = false;
    if (method === TwoFactorMethod.WHATSAPP) {
      valid = Boolean(challenge.codeHash) &&
        this.hashToken(dto.code) === challenge.codeHash;
    } else if (secret) {
      valid = authenticator.check(dto.code, secret);
    }
    if (!valid) {
      throw new UnauthorizedException('Invalid code');
    }
    await this.prisma.twoFactorChallenge.update({
      where: { id: dto.challengeId },
      data: { resolved: true },
    });
    const sessionRole = challenge.sessionRole ?? challenge.account.role;
    const tokens = await this.issueTokens(challenge.account, { sessionRole });
    await this.recordLoginHistory(
      challenge.account,
      sessionRole,
      LoginEventSource.TWO_FACTOR,
      meta,
    );
    return {
      requiresTwoFactor: false,
      ...tokens,
    };
  }

  async refresh(refreshToken: string) {
    const { account, sessionRole, sessionSubjectId, activeProduct, activeProductRole, productSubjectId } =
      await this.findRefreshToken(refreshToken);
    await this.revokeRefreshToken(refreshToken);
    const tokens = await this.issueTokens(account, {
      sessionRole: sessionRole ?? account.role,
      sessionSubjectId: sessionSubjectId ?? undefined,
      productAccess:
        activeProduct && activeProductRole
          ? {
              id: '',
              product: activeProduct,
              role: activeProductRole,
              subjectId: productSubjectId,
              status: ProductAccessStatus.ACTIVE,
          }
          : undefined,
    });
    const availableProductAccess = await this.getAvailableProductAccess(account.id);
    return { ...tokens, availableProductAccess };
  }

  async logout(refreshToken: string) {
    if (!refreshToken) {
      return { success: true };
    }
    await this.revokeRefreshToken(refreshToken);
    return { success: true };
  }

  async impersonateDoctor(doctorId: string) {
    const account = await this.prisma.account.findFirst({
      where: { doctorId },
    });
    if (!account) {
      throw new NotFoundException('Doctor no encontrado');
    }
    if (account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Cuenta inactiva');
    }
    return this.issueTokens(account, { sessionRole: AccountRole.DOCTOR });
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
    if (!account) {
      throw new BadRequestException('No hay cuenta para los datos suministrados');
    }
    await this.ensureRecoveryProfile(account);

    await this.prisma.passwordRecovery.deleteMany({
      where: { accountId: account.id },
    });

    const code = this.generateRecoveryCode();
    const codeHash = this.hashToken(code);
    const expiresAt = new Date(Date.now() + this.recoveryCodeTtl * 1000);
    const magicToken = randomBytes(48).toString('hex');
    const magicTokenHash = this.hashToken(magicToken);
    const magicExpiresAt = new Date(Date.now() + this.recoveryCodeTtl * 1000);
    const recovery = await this.prisma.passwordRecovery.create({
      data: {
        accountId: account.id,
        codeHash,
        expiresAt,
        magicTokenHash,
        magicExpiresAt,
      },
    });

      const name = await this.resolveRecoveryName(account);
    const recoveryLink = this.buildRecoveryLink(this.recoveryLinkBase, magicToken);

    if (normalizedEmail) {
      await this.notifications.sendPasswordRecoveryEmail({
        email: account.email,
        name,
        code,
        link: recoveryLink,
        ttlSeconds: this.recoveryCodeTtl,
      });
    } else if (account.phoneNumber) {
      await this.notifications.sendPasswordRecoveryWhatsapp({
        phoneNumber: account.phoneNumber,
        name,
        code,
        link: recoveryLink,
        ttlSeconds: this.recoveryCodeTtl,
      });
    } else {
      throw new BadRequestException('No hay cuenta con WhatsApp disponible');
    }

    return {
      recoveryId: recovery.id,
      expiresAt: recovery.expiresAt.toISOString(),
    };
  }

  async startPasswordRecoveryForAccount(
    authUserId: string,
    dto: PasswordChangeStartDto,
  ) {
    const account = await this.prisma.account.findUnique({
      where: { id: authUserId },
    });
    if (!account || account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Cuenta no disponible');
    }
    if (account.deletedAt) {
      throw new BadRequestException('La cuenta ya fue eliminada');
    }

    const channel = this.resolveAccountDeletionChannel(account, dto.channel);
    const destination =
      channel === AccountDeletionChannel.EMAIL
        ? account.email
        : account.phoneNumber;
    if (!destination) {
      throw new BadRequestException(
        'No hay un canal disponible para enviar el codigo',
      );
    }

    await this.ensureRecoveryProfile(account);
    await this.prisma.passwordRecovery.deleteMany({
      where: { accountId: account.id },
    });

    const code = this.generateRecoveryCode();
    const codeHash = this.hashToken(code);
    const expiresAt = new Date(Date.now() + this.recoveryCodeTtl * 1000);
    const magicToken = randomBytes(48).toString('hex');
    const magicTokenHash = this.hashToken(magicToken);
    const magicExpiresAt = new Date(Date.now() + this.recoveryCodeTtl * 1000);
    const recovery = await this.prisma.passwordRecovery.create({
      data: {
        accountId: account.id,
        codeHash,
        expiresAt,
        magicTokenHash,
        magicExpiresAt,
      },
    });

    const name = await this.resolveRecoveryName(account);
    const recoveryLink = this.buildRecoveryLink(this.recoveryLinkBase, magicToken);

    if (channel === AccountDeletionChannel.EMAIL) {
      await this.notifications.sendPasswordRecoveryEmail({
        email: account.email,
        name,
        code,
        link: recoveryLink,
        ttlSeconds: this.recoveryCodeTtl,
      });
    } else if (account.phoneNumber) {
      await this.notifications.sendPasswordRecoveryWhatsapp({
        phoneNumber: account.phoneNumber,
        name,
        code,
        link: recoveryLink,
        ttlSeconds: this.recoveryCodeTtl,
      });
    } else {
      throw new BadRequestException('No hay cuenta con WhatsApp disponible');
    }

    return {
      recoveryId: recovery.id,
      expiresAt: recovery.expiresAt.toISOString(),
      channel,
      destinationMasked: this.maskDestination(channel, destination),
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
        magicConsumedAt: recovery.magicConsumedAt ?? new Date(),
      },
    });

    return {
      resetToken,
      resetExpiresAt: resetExpiresAt.toISOString(),
    };
  }

  async checkPhoneAvailability(dto: PhoneAvailabilityDto) {
    const normalizedPhone = this.normalizePhoneNumber(dto.phoneNumber);
    const existing = await this.prisma.account.findUnique({
      where: { phoneNumber: normalizedPhone },
      select: { id: true },
    });
    if (!existing) {
      return { available: true };
    }
    if (dto.authUserId && existing.id === dto.authUserId) {
      return { available: true };
    }
    throw new ConflictException('El numero de telefono ya esta registrado');
  }

  async verifyPasswordRecoveryLink(dto: RecoveryLinkDto) {
    const magicTokenHash = this.hashToken(dto.token);
    const recovery = await this.prisma.passwordRecovery.findFirst({
      where: { magicTokenHash },
      include: { account: true },
    });
    if (
      !recovery ||
      !recovery.magicExpiresAt ||
      recovery.magicExpiresAt < new Date() ||
      recovery.magicConsumedAt ||
      recovery.consumedAt
    ) {
      throw new UnauthorizedException('Recovery link expired');
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
        magicConsumedAt: new Date(),
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

  async startPhoneChange(authUserId: string, dto: PhoneChangeStartDto) {
    const account = await this.prisma.account.findUnique({
      where: { id: authUserId },
    });
    if (!account || account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Cuenta no disponible');
    }
    if (account.deletedAt) {
      throw new BadRequestException('La cuenta ya fue eliminada');
    }

    const channel = this.resolvePhoneChangeChannel(account, dto.channel);
    const destination =
      channel === AccountVerificationChannel.EMAIL
        ? account.email
        : account.phoneNumber;

    if (!destination) {
      throw new BadRequestException(
        'No hay un canal disponible para enviar el codigo',
      );
    }

    await this.prisma.accountPhoneChange.deleteMany({
      where: { accountId: account.id },
    });

    const code = this.generateRecoveryCode();
    const codeHash = this.hashToken(code);
    const expiresAt = new Date(Date.now() + this.recoveryCodeTtl * 1000);

    const change = await this.prisma.accountPhoneChange.create({
      data: {
        accountId: account.id,
        channel,
        destination,
        codeHash,
        expiresAt,
        maxAttempts: this.recoveryMaxAttempts,
      },
    });

    const name = await this.resolveRecoveryName(account);
    if (channel === AccountVerificationChannel.EMAIL) {
      await this.notifications.sendPhoneChangeEmail({
        email: account.email,
        name,
        code,
        ttlSeconds: this.recoveryCodeTtl,
      });
    } else if (account.phoneNumber) {
      await this.notifications.sendPhoneChangeWhatsapp({
        phoneNumber: account.phoneNumber,
        name,
        code,
        ttlSeconds: this.recoveryCodeTtl,
      });
    } else {
      throw new BadRequestException('No hay cuenta con WhatsApp disponible');
    }

    return {
      changeId: change.id,
      channel,
      destinationMasked: this.maskDestination(channel, destination),
      expiresAt: change.expiresAt.toISOString(),
    };
  }

  async verifyPhoneChange(authUserId: string, dto: PhoneChangeVerifyDto) {
    const change = await this.prisma.accountPhoneChange.findUnique({
      where: { id: dto.changeId },
    });
    if (!change || change.expiresAt < new Date() || change.consumedAt) {
      throw new UnauthorizedException('Codigo expirado');
    }
    if (change.accountId !== authUserId) {
      throw new UnauthorizedException('Codigo invalido');
    }
    if (change.attempts >= change.maxAttempts) {
      throw new UnauthorizedException('Codigo bloqueado');
    }

    const codeHash = this.hashToken(dto.code);
    if (codeHash !== change.codeHash) {
      await this.prisma.accountPhoneChange.update({
        where: { id: change.id },
        data: { attempts: { increment: 1 } },
      });
      throw new UnauthorizedException('Codigo invalido');
    }

    const token = randomBytes(48).toString('hex');
    const tokenHash = this.hashToken(token);
    const tokenExpiresAt = new Date(Date.now() + this.recoveryResetTtl * 1000);

    await this.prisma.accountPhoneChange.update({
      where: { id: change.id },
      data: {
        tokenHash,
        tokenExpiresAt,
        verifiedAt: new Date(),
      },
    });

    return {
      token,
      tokenExpiresAt: tokenExpiresAt.toISOString(),
    };
  }

  async completePhoneChange(authUserId: string, dto: PhoneChangeCompleteDto) {
    const tokenHash = this.hashToken(dto.token);
    const change = await this.prisma.accountPhoneChange.findFirst({
      where: { tokenHash },
    });
    if (
      !change ||
      !change.tokenExpiresAt ||
      change.tokenExpiresAt < new Date() ||
      change.consumedAt
    ) {
      throw new UnauthorizedException('Token expirado');
    }
    if (change.accountId !== authUserId) {
      throw new UnauthorizedException('Token invalido');
    }

    const account = await this.prisma.account.findUnique({
      where: { id: authUserId },
      select: { status: true, deletedAt: true },
    });
    if (!account || account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Cuenta no disponible');
    }
    if (account.deletedAt) {
      throw new BadRequestException('La cuenta ya fue eliminada');
    }

    const normalizedPhone = this.normalizePhoneNumber(dto.phoneNumber);
    const existing = await this.prisma.account.findUnique({
      where: { phoneNumber: normalizedPhone },
      select: { id: true },
    });
    if (existing && existing.id !== authUserId) {
      throw new ConflictException('El numero de telefono ya esta registrado');
    }

    await this.prisma.$transaction([
      this.prisma.account.update({
        where: { id: authUserId },
        data: {
          phoneNumber: normalizedPhone,
        },
      }),
      this.prisma.accountPhoneChange.update({
        where: { id: change.id },
        data: { consumedAt: new Date() },
      }),
    ]);

    return { success: true };
  }

  async startAccountDeletion(
    authUserId: string,
    dto: AccountDeletionStartDto,
    meta?: RequestMeta,
  ) {
    const account = await this.prisma.account.findUnique({
      where: { id: authUserId },
    });
    if (!account || account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Cuenta no disponible');
    }
    if (account.deletedAt) {
      throw new BadRequestException('La cuenta ya fue eliminada');
    }

    const channel = this.resolveAccountDeletionChannel(account, dto.channel);
    const destination =
      channel === AccountDeletionChannel.EMAIL
        ? account.email
        : account.phoneNumber;

    if (!destination) {
      throw new BadRequestException(
        'No hay un canal disponible para validar el borrado de cuenta',
      );
    }

    await this.prisma.accountDeletionChallenge.deleteMany({
      where: {
        accountId: account.id,
        consumedAt: null,
      },
    });

    const code = this.generateRecoveryCode();
    const codeHash = this.hashToken(code);
    const expiresAt = new Date(Date.now() + this.accountDeletionCodeTtl * 1000);
    const challenge = await this.prisma.accountDeletionChallenge.create({
      data: {
        accountId: account.id,
        channel,
        destination,
        codeHash,
        expiresAt,
        maxAttempts: this.accountDeletionMaxAttempts,
      },
    });

    const name = await this.resolveRecoveryName(account);
    if (channel === AccountDeletionChannel.EMAIL) {
      await this.notifications.sendAccountDeletionEmail({
        email: destination,
        name,
        code,
        ttlSeconds: this.accountDeletionCodeTtl,
      });
    } else {
      await this.notifications.sendAccountDeletionWhatsapp({
        phoneNumber: destination,
        name,
        code,
        ttlSeconds: this.accountDeletionCodeTtl,
      });
    }

    return {
      challengeId: challenge.id,
      channel,
      destinationMasked: this.maskDestination(channel, destination),
      expiresAt: challenge.expiresAt.toISOString(),
    };
  }

  async confirmAccountDeletion(
    authUserId: string,
    dto: AccountDeletionConfirmDto,
    meta?: RequestMeta,
  ) {
    const challenge = await this.prisma.accountDeletionChallenge.findUnique({
      where: { id: dto.challengeId },
      include: { account: true },
    });
    if (!challenge || challenge.accountId !== authUserId) {
      throw new UnauthorizedException('Codigo invalido');
    }
    if (challenge.consumedAt || challenge.expiresAt < new Date()) {
      throw new UnauthorizedException('Codigo expirado');
    }
    if (challenge.attempts >= challenge.maxAttempts) {
      throw new UnauthorizedException('Codigo bloqueado');
    }
    const codeHash = this.hashToken(dto.code);
    if (codeHash !== challenge.codeHash) {
      await this.prisma.accountDeletionChallenge.update({
        where: { id: challenge.id },
        data: { attempts: { increment: 1 } },
      });
      throw new UnauthorizedException('Codigo invalido');
    }

    await this.prisma.accountDeletionChallenge.update({
      where: { id: challenge.id },
      data: {
        verifiedAt: new Date(),
        consumedAt: new Date(),
      },
    });

    const result = await this.executeAccountDeletion(
      challenge.account,
      challenge.channel,
      meta,
    );

    if (challenge.account.role === AccountRole.DOCTOR) {
      const doctorId =
        challenge.account.doctorId ?? challenge.account.subjectId ?? '';
      if (doctorId) {
        try {
          await this.rabbitmq.publishDoctorEvent({
            type: 'DoctorDeleted',
            routingKey: 'doctors.deleted',
            correlationId: dto.challengeId,
            data: { doctorId },
          });
        } catch (error) {
          this.logger.warn(
            `No se pudo publicar DoctorDeleted (${doctorId})`,
            error as Error,
          );
        }
      }
    }

    return {
      success: result.status === AccountDeletionAuditStatus.COMPLETED,
      status: result.status,
      deletedAt: result.deletedAt.toISOString(),
      logs: result.logs,
      error: result.error,
    };
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
    const sanitizedRedirect = this.sanitizeRedirect(redirect, this.googleSuccessRedirect);
    const state = this.createOAuthState({ role, redirect: sanitizedRedirect }, this.googleStateTtl, 'google');
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

  async handleGoogleOAuthCallback(code?: string, state?: string, meta?: RequestMeta) {
    try {
      if (!code || !state) {
        throw new BadRequestException('Missing OAuth code or state');
      }
      const entry = this.verifyOAuthState(state, 'google');
      if (!this.googleClientId || !this.googleClientSecret || !this.googleRedirectUri) {
        throw new ServiceUnavailableException('Google OAuth no est?? configurado');
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
        return this.buildOauthErrorResult('No fue posible validar Google', this.googleErrorRedirect, this.googleSuccessRedirect);
      }
      const tokenPayload = (await tokenResponse.json()) as {
        access_token?: string;
        id_token?: string;
        expires_in?: number;
        scope?: string;
        token_type?: string;
      };
      if (!tokenPayload.access_token) {
        return this.buildOauthErrorResult('Google no devolvi?? access token', this.googleErrorRedirect, this.googleSuccessRedirect);
      }

      const userinfoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: {
          Authorization: `Bearer ${tokenPayload.access_token}`,
        },
      });
      if (!userinfoResponse.ok) {
        const errorText = await userinfoResponse.text();
        this.logger.error(`Google userinfo error: ${errorText}`);
        return this.buildOauthErrorResult('No fue posible obtener datos de Google', this.googleErrorRedirect, this.googleSuccessRedirect);
      }
      const profile = (await userinfoResponse.json()) as {
        sub?: string;
        email?: string;
        email_verified?: boolean;
        name?: string;
      };

      if (!profile.email) {
        return this.buildOauthErrorResult('Google no devolvi?? email', this.googleErrorRedirect, this.googleSuccessRedirect);
      }
      if (profile.email_verified === false) {
        return this.buildOauthErrorResult('Email de Google no verificado', this.googleErrorRedirect, this.googleSuccessRedirect);
      }

      const normalizedEmail = profile.email.trim().toLowerCase();
      const existing = await this.prisma.account.findUnique({
        where: { email: normalizedEmail },
      });
      const hasRoleProfileGoogle = existing && existing.role !== entry.role
        ? await this.prisma.accountRoleProfile.findUnique({
            where: { accountId_role: { accountId: existing.id, role: entry.role } },
          })
        : null;
      const allowRoleSwitchGoogle =
        (Boolean(existing) && existing?.role === AccountRole.DOCTOR && entry.role === AccountRole.PATIENT) ||
        Boolean(hasRoleProfileGoogle);
      if (existing && existing.role !== entry.role && !allowRoleSwitchGoogle) {
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
        const employerId = entry.role === AccountRole.EMPLOYER ? randomUUID() : null;
        const onboardingStatus =
          entry.role === AccountRole.DOCTOR ||
          entry.role === AccountRole.CLINIC ||
          entry.role === AccountRole.EMPLOYER
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
            employerId,
            onboardingStatus,
          },
        });
        await this.publishUserRegisteredEvent(account, {
          companyName: profile.name?.trim() || normalizedEmail.split('@')[0],
        });
      }

      const sessionRole =
        (existing && existing.role !== entry.role && allowRoleSwitchGoogle)
          ? entry.role
          : account.role;
      const tokens = await this.issueTokens(account, { sessionRole });
      await this.recordLoginHistory(account, sessionRole, LoginEventSource.OAUTH_GOOGLE, meta);
      const redirect = entry.redirect ?? this.googleSuccessRedirect;
      if (redirect) {
        const url = new URL(redirect);
        url.searchParams.set('accessToken', tokens.accessToken);
        url.searchParams.set('refreshToken', tokens.refreshToken);
        url.searchParams.set('expiresIn', String(tokens.accessTokenExpiresIn));
        return { redirect: url.toString(), payload: null };
      }
      return { redirect: null, payload: tokens };
    } catch (error) {
      if (error instanceof BadRequestException || error instanceof UnauthorizedException || error instanceof ConflictException) {
        return this.buildOauthErrorResult(error.message, this.googleErrorRedirect, this.googleSuccessRedirect);
      }
      throw error;
    }
  }

  getAppleOAuthUrl(roleInput: string, redirect?: string) {
    if (!this.appleClientId || !this.appleRedirectUri) {
      throw new ServiceUnavailableException('Apple OAuth no está configurado');
    }
    const role = this.parseRole(roleInput);
    const sanitizedRedirect = this.sanitizeRedirect(redirect, this.appleSuccessRedirect);
    const state = this.createOAuthState({ role, redirect: sanitizedRedirect }, this.appleStateTtl, 'apple');
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

  async handleAppleOAuthCallback(code?: string, state?: string, meta?: RequestMeta) {
    if (!code || !state) {
      throw new BadRequestException('Missing OAuth code or state');
    }
    const entry = this.verifyOAuthState(state, 'apple');
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
    const hasRoleProfileApple = existing && existing.role !== entry.role
      ? await this.prisma.accountRoleProfile.findUnique({
          where: { accountId_role: { accountId: existing.id, role: entry.role } },
        })
      : null;
    const allowRoleSwitchApple =
      (Boolean(existing) && existing?.role === AccountRole.DOCTOR && entry.role === AccountRole.PATIENT) ||
      Boolean(hasRoleProfileApple);
    if (existing && existing.role !== entry.role && !allowRoleSwitchApple) {
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
      const employerId = entry.role === AccountRole.EMPLOYER ? randomUUID() : null;
      const onboardingStatus =
        entry.role === AccountRole.DOCTOR ||
        entry.role === AccountRole.CLINIC ||
        entry.role === AccountRole.EMPLOYER
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
          employerId,
          onboardingStatus,
        },
      });
      await this.publishUserRegisteredEvent(account, {
        companyName: normalizedEmail.split('@')[0],
      });
    }

    const sessionRole =
      (existing && existing.role !== entry.role && allowRoleSwitchApple)
        ? entry.role
        : account.role;
    const tokens = await this.issueTokens(account, { sessionRole });
    await this.recordLoginHistory(account, sessionRole, LoginEventSource.OAUTH_APPLE, meta);
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

  async getTwoFactorStatus(authUserId: string) {
    const account = await this.findAccountById(authUserId);
    const method = account.twoFactorEnabled
      ? this.resolveTwoFactorMethod(account)
      : null;
    return {
      enabled: account.twoFactorEnabled,
      method,
      phoneNumberMasked: account.phoneNumber
        ? this.maskDestination(AccountVerificationChannel.WHATSAPP, account.phoneNumber)
        : null,
      hasAuthenticatorApp: Boolean(account.twoFactorSecret),
    };
  }

  async setupTwoFactor(authUserId: string, dto: TwoFactorSetupDto) {
    const account = await this.findAccountById(authUserId);
    if (dto.method === TwoFactorMethod.TOTP) {
      const secret = authenticator.generateSecret();
      await this.prisma.account.update({
        where: { id: account.id },
        data: {
          pendingTwoFactorSecret: secret,
        },
      });
      const issuer = this.config.get<string>('MFA_ISSUER', 'MeuSalud');
      return {
        method: TwoFactorMethod.TOTP,
        secret,
        otpAuthUrl: authenticator.keyuri(account.email, issuer, secret),
        challengeId: null,
        expiresAt: null,
        destinationMasked: null,
      };
    }
    if (!account.phoneNumber) {
      throw new BadRequestException('No hay WhatsApp disponible');
    }
    const challenge = await this.createTwoFactorChallenge(account, {
      method: TwoFactorMethod.WHATSAPP,
      purpose: TwoFactorChallengePurpose.SETUP,
      destination: account.phoneNumber,
      generateCode: true,
    });
    await this.sendWhatsAppTwoFactorCode(account, challenge);
    return {
      method: TwoFactorMethod.WHATSAPP,
      secret: null,
      otpAuthUrl: null,
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt.toISOString(),
      destinationMasked: this.maskDestination(AccountVerificationChannel.WHATSAPP, account.phoneNumber),
    };
  }

  async confirmTwoFactor(authUserId: string, dto: TwoFactorCodeDto) {
    const account = await this.findAccountById(authUserId);
    if (dto.challengeId) {
      const challenge = await this.prisma.twoFactorChallenge.findUnique({
        where: { id: dto.challengeId },
      });
      if (
        !challenge ||
        challenge.accountId !== account.id ||
        challenge.purpose !== TwoFactorChallengePurpose.SETUP ||
        challenge.method !== TwoFactorMethod.WHATSAPP ||
        challenge.expiresAt < new Date() ||
        challenge.resolved ||
        !challenge.codeHash
      ) {
        throw new UnauthorizedException('Challenge expired');
      }
      if (this.hashToken(dto.code) !== challenge.codeHash) {
        throw new UnauthorizedException('Invalid code');
      }
      await this.prisma.$transaction([
        this.prisma.twoFactorChallenge.update({
          where: { id: challenge.id },
          data: { resolved: true },
        }),
        this.prisma.account.update({
          where: { id: account.id },
          data: {
            twoFactorEnabled: true,
            twoFactorMethod: TwoFactorMethod.WHATSAPP,
            twoFactorSecret: null,
            pendingTwoFactorSecret: null,
          },
        }),
      ]);
      return { twoFactorEnabled: true, method: TwoFactorMethod.WHATSAPP };
    }

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
        twoFactorMethod: TwoFactorMethod.TOTP,
        pendingTwoFactorSecret: null,
      },
    });
    return { twoFactorEnabled: true, method: TwoFactorMethod.TOTP };
  }

  async startDisableTwoFactor(authUserId: string) {
    const account = await this.findAccountById(authUserId);
    if (!account.twoFactorEnabled) {
      throw new BadRequestException('Two-factor is not enabled');
    }
    const method = this.resolveTwoFactorMethod(account);
    if (method !== TwoFactorMethod.WHATSAPP) {
      return {
        method,
        challengeId: null,
        expiresAt: null,
        destinationMasked: null,
      };
    }
    if (!account.phoneNumber) {
      throw new BadRequestException('No hay WhatsApp disponible');
    }
    const challenge = await this.createTwoFactorChallenge(account, {
      method: TwoFactorMethod.WHATSAPP,
      purpose: TwoFactorChallengePurpose.DISABLE,
      destination: account.phoneNumber,
      generateCode: true,
    });
    await this.sendWhatsAppTwoFactorCode(account, challenge);
    return {
      method,
      challengeId: challenge.id,
      expiresAt: challenge.expiresAt.toISOString(),
      destinationMasked: this.maskDestination(AccountVerificationChannel.WHATSAPP, account.phoneNumber),
    };
  }

  async disableTwoFactor(authUserId: string, dto: TwoFactorCodeDto) {
    const account = await this.findAccountById(authUserId);
    if (!account.twoFactorEnabled) {
      throw new BadRequestException('Two-factor is not enabled');
    }
    const method = this.resolveTwoFactorMethod(account);
    if (method === TwoFactorMethod.WHATSAPP) {
      if (!dto.challengeId) {
        throw new BadRequestException('challengeId es requerido');
      }
      const challenge = await this.prisma.twoFactorChallenge.findUnique({
        where: { id: dto.challengeId },
      });
      if (
        !challenge ||
        challenge.accountId !== account.id ||
        challenge.purpose !== TwoFactorChallengePurpose.DISABLE ||
        challenge.method !== TwoFactorMethod.WHATSAPP ||
        challenge.expiresAt < new Date() ||
        challenge.resolved ||
        !challenge.codeHash
      ) {
        throw new UnauthorizedException('Challenge expired');
      }
      if (this.hashToken(dto.code) !== challenge.codeHash) {
        throw new UnauthorizedException('Invalid code');
      }
      await this.prisma.twoFactorChallenge.update({
        where: { id: challenge.id },
        data: { resolved: true },
      });
    } else {
      if (!account.twoFactorSecret || !authenticator.check(dto.code, account.twoFactorSecret)) {
        throw new UnauthorizedException('Invalid code');
      }
    }
    await this.prisma.account.update({
      where: { id: account.id },
      data: {
        twoFactorEnabled: false,
        twoFactorMethod: null,
        twoFactorSecret: null,
        pendingTwoFactorSecret: null,
      },
    });
    await this.prisma.twoFactorChallenge.deleteMany({
      where: { accountId: account.id },
    });
    return { twoFactorEnabled: false, method: null };
  }

  private async issueTokens(
    account: Account,
    options?: {
      scope?: string;
      sessionRole?: AccountRole;
      sessionSubjectId?: string | null;
      productAccess?: ProductAccessContext | null;
    },
  ) {
    const sessionRole = options?.sessionRole ?? account.role;
    let sessionSubjectId = options?.sessionSubjectId ?? null;
    let clinicSessionSubjectId: string | null = null;
    let clinicSessionOnboardingStatus: OnboardingStatus = account.onboardingStatus;
    let employerSessionEmployerId: string | null = null;
    let employerSessionOnboardingStatus: OnboardingStatus = account.onboardingStatus;
    let accountForSession = account;
    const payload: Record<string, unknown> = {
      sub: account.id,
      role: sessionRole,
    };
    if (sessionRole === AccountRole.PATIENT) {
      if (account.role === AccountRole.PATIENT) {
        accountForSession = await this.ensurePatientSubjectId(account);
        sessionSubjectId = accountForSession.subjectId ?? null;
      } else {
        // Buscar en role profiles si existe un perfil de paciente
        const patientProfile = await this.prisma.accountRoleProfile.findUnique({
          where: { accountId_role: { accountId: account.id, role: AccountRole.PATIENT } },
        });
        if (patientProfile?.subjectId) {
          sessionSubjectId = patientProfile.subjectId;
        } else {
          sessionSubjectId = await this.resolvePatientIdForSession(account, sessionSubjectId);
          // Persistir el patientId en el profile para futuras sesiones
          if (sessionSubjectId && patientProfile) {
            await this.prisma.accountRoleProfile.update({
              where: { accountId_role: { accountId: account.id, role: AccountRole.PATIENT } },
              data: { subjectId: sessionSubjectId },
            });
          }
        }
      }
      if (sessionSubjectId) {
        payload.patientId = sessionSubjectId;
        payload.subjectId = sessionSubjectId;
      }
      payload.onboardingRequired = false;
    } else if (sessionRole === AccountRole.DOCTOR) {
      const doctorId =
        account.doctorId ?? (account.role === AccountRole.DOCTOR ? account.subjectId ?? null : null);
      if (doctorId) {
        payload.doctorId = doctorId;
      }
      // Leer onboardingStatus del profile si el rol principal no es DOCTOR
      let doctorOnboardingStatus: OnboardingStatus;
      if (account.role === AccountRole.DOCTOR) {
        doctorOnboardingStatus = account.onboardingStatus;
      } else {
        const doctorProfile = await this.prisma.accountRoleProfile.findUnique({
          where: { accountId_role: { accountId: account.id, role: AccountRole.DOCTOR } },
        });
        doctorOnboardingStatus = doctorProfile?.onboardingStatus ?? OnboardingStatus.PENDING;
      }
      payload.onboardingRequired = doctorOnboardingStatus !== OnboardingStatus.COMPLETE;
    } else if (sessionRole === AccountRole.CLINIC) {
      // Leer subjectId y onboardingStatus del profile si el rol principal no es CLINIC
      if (account.role === AccountRole.CLINIC) {
        clinicSessionSubjectId = account.subjectId ?? null;
        clinicSessionOnboardingStatus = account.onboardingStatus;
      } else {
        const clinicProfile = await this.prisma.accountRoleProfile.findUnique({
          where: { accountId_role: { accountId: account.id, role: AccountRole.CLINIC } },
        });
        clinicSessionSubjectId = clinicProfile?.subjectId ?? null;
        clinicSessionOnboardingStatus = clinicProfile?.onboardingStatus ?? OnboardingStatus.PENDING;
      }
      if (clinicSessionSubjectId) {
        payload.clinicId = clinicSessionSubjectId;
        payload.subjectId = clinicSessionSubjectId;
      }
      payload.onboardingRequired = clinicSessionOnboardingStatus !== OnboardingStatus.COMPLETE;
      sessionSubjectId = clinicSessionSubjectId;
    } else if (sessionRole === AccountRole.EMPLOYER) {
      if (account.role === AccountRole.EMPLOYER) {
        employerSessionEmployerId = account.employerId ?? account.subjectId ?? null;
        employerSessionOnboardingStatus = account.onboardingStatus;
      } else {
        const employerProfile = await this.prisma.accountRoleProfile.findUnique({
          where: { accountId_role: { accountId: account.id, role: AccountRole.EMPLOYER } },
        });
        employerSessionEmployerId = employerProfile?.subjectId ?? null;
        employerSessionOnboardingStatus = employerProfile?.onboardingStatus ?? OnboardingStatus.PENDING;
      }
      if (employerSessionEmployerId) {
        payload.employerId = employerSessionEmployerId;
        payload.subjectId = employerSessionEmployerId;
      }
      payload.onboardingRequired = employerSessionOnboardingStatus !== OnboardingStatus.COMPLETE;
      sessionSubjectId = employerSessionEmployerId;
    } else if (sessionRole === AccountRole.COLLABORATOR) {
      if (account.role === AccountRole.DOCTOR) {
        throw new BadRequestException(
          'No se permite iniciar sesion como colaborador con una cuenta de doctor',
        );
      }
      const collaborator = await this.prisma.collaborator.findUnique({
        where: { accountId: account.id },
        include: {
          permissions: { include: { permission: true } },
          agendas: true,
        },
      });
      if (!collaborator || collaborator.status !== CollaboratorStatus.ACTIVE) {
        throw new UnauthorizedException('Account disabled');
      }
      payload.doctorId = collaborator.doctorId;
      payload.collaboratorId = collaborator.id;
      payload.permissions = collaborator.permissions.map(
        (entry) => entry.permission.key,
      );
      payload.agendaIds = collaborator.agendas.map(
        (agenda) => agenda.agendaId,
      );
      payload.onboardingRequired = false;
    } else {
      payload.onboardingRequired = false;
    }
    if (options?.scope) {
      payload.scope = options.scope;
    }
    if (options?.productAccess) {
      payload.activeProduct = options.productAccess.product;
      payload.activeProductRole = options.productAccess.role;
      if (options.productAccess.id) {
        payload.productAccessId = options.productAccess.id;
      }
      if (options.productAccess.subjectId) {
        payload.productSubjectId = options.productAccess.subjectId;
      }
      payload.productAccessStatus = options.productAccess.status;
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
        sessionRole,
        sessionSubjectId: sessionSubjectId ?? undefined,
        activeProduct: options?.productAccess?.product,
        activeProductRole: options?.productAccess?.role,
        productSubjectId: options?.productAccess?.subjectId ?? undefined,
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
        phoneNumber: account.phoneNumber,
        role: sessionRole,
        subjectId:
          sessionRole === AccountRole.PATIENT
            ? sessionSubjectId
            : sessionRole === AccountRole.CLINIC
              ? clinicSessionSubjectId
              : sessionRole === AccountRole.EMPLOYER
                ? employerSessionEmployerId
                : null,
        doctorId:
          sessionRole === AccountRole.DOCTOR || sessionRole === AccountRole.COLLABORATOR
            ? (payload.doctorId as string | null | undefined) ?? null
            : null,
        clinicId:
          sessionRole === AccountRole.CLINIC ? clinicSessionSubjectId : null,
        employerId:
          sessionRole === AccountRole.EMPLOYER ? employerSessionEmployerId : null,
        onboardingStatus:
          sessionRole === AccountRole.CLINIC
            ? clinicSessionOnboardingStatus
            : sessionRole === AccountRole.EMPLOYER
              ? employerSessionOnboardingStatus
              : account.onboardingStatus,
        activeProduct: options?.productAccess?.product ?? null,
        activeProductRole: options?.productAccess?.role ?? null,
        productSubjectId: options?.productAccess?.subjectId ?? null,
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

    const tokens = await this.issueTokens(stored.account, { scope: stored.scope });
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

  private async completeClinicDoctorInviteRegistration(account: Account, inviteToken: string) {
    if (account.role !== AccountRole.DOCTOR || !account.doctorId) {
      throw new BadRequestException('La cuenta no corresponde a un medico');
    }

    const url = `${this.clinicsInternalBaseUrl.replace(/\/$/, '')}/clinics/internal/doctors/invites/${encodeURIComponent(inviteToken)}/complete-registration`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-role': 'SYSTEM',
        'x-auth-user-id': account.id,
        'x-subject-id': account.doctorId,
      },
      body: JSON.stringify({
        authUserId: account.id,
        doctorId: account.doctorId,
        email: account.email,
      }),
    });

    if (response.ok) {
      return;
    }

    const body = await response.text();
    this.logger.error(
      `No se pudo completar invitacion de clinica para medico (status ${response.status}): ${body}`,
    );

    if (response.status === 400 || response.status === 403 || response.status === 404) {
      throw new BadRequestException('Invitacion de clinica invalida o expirada');
    }

    throw new ServiceUnavailableException('No se pudo completar la invitacion de clinica');
  }

  private async recordLoginHistory(
    account: Account,
    sessionRole: AccountRole,
    source: LoginEventSource,
    meta?: RequestMeta,
  ) {
    const ipAddress = this.extractClientIp(meta);
    await this.prisma.loginHistory.create({
      data: {
        accountId: account.id,
        role: sessionRole,
        source,
        ipAddress,
        userAgent: meta?.userAgent ?? null,
      },
    });
  }

  async getLoginHistory(authUserId: string, limit = 20) {
    const safeLimit = Math.min(Math.max(limit, 1), 50);
    return this.prisma.loginHistory.findMany({
      where: { accountId: authUserId },
      orderBy: { createdAt: 'desc' },
      take: safeLimit,
      select: {
        id: true,
        role: true,
        source: true,
        ipAddress: true,
        userAgent: true,
        createdAt: true,
      },
    });
  }

  private async buildIdentitySnapshot(
    account: Account,
    doctorId: string | null,
    patientId: string | null,
  ) {
    const email = account.email?.trim().toLowerCase() ?? null;
    const phoneNumber = account.phoneNumber ?? null;
    let doctorDocumentNumber: string | null = null;
    let doctorDocumentType: string | null = null;
    let patientDocumentNumber: string | null = null;
    let patientDocumentType: string | null = null;

    if (doctorId) {
      const rows = await this.prisma.$queryRaw<
        Array<{ documentNumber: string | null; legalDocumentType: string | null }>
      >`SELECT "documentNumber", "legalDocumentType" FROM "doctors"."Doctor" WHERE "id" = ${doctorId}`;
      doctorDocumentNumber = rows[0]?.documentNumber ?? null;
      doctorDocumentType = rows[0]?.legalDocumentType ?? null;
    }

    if (patientId) {
      const rows = await this.prisma.$queryRaw<
        Array<{ documentNumber: string | null; documentType: string | null }>
      >`SELECT "documentNumber", "documentType" FROM "users"."Patient" WHERE "id" = ${patientId}`;
      patientDocumentNumber = rows[0]?.documentNumber ?? null;
      patientDocumentType = rows[0]?.documentType ?? null;
    }

    return {
      email,
      phoneNumber,
      doctorId,
      patientId,
      doctorDocumentNumber,
      doctorDocumentType,
      patientDocumentNumber,
      patientDocumentType,
    };
  }

  private async recordIdentityReuse(
    account: Account,
    email: string,
    phoneNumber: string,
  ) {
    const matches = await this.prisma.$queryRaw<
      Array<{ id: string; accountId: string; detailsJson: unknown }>
    >`
      SELECT "id", "accountId", "detailsJson"
      FROM "AccountDeletionAudit"
      WHERE ("detailsJson"->'identity'->>'email' = ${email})
         OR ("detailsJson"->'identity'->>'phoneNumber' = ${phoneNumber})
      ORDER BY "createdAt" DESC
      LIMIT 1
    `;

    const match = matches[0];
    if (!match) {
      return;
    }

    const details =
      typeof match.detailsJson === 'object' && match.detailsJson !== null
        ? (match.detailsJson as { identity?: Record<string, unknown> })
        : undefined;
    const identity = details?.identity ?? {};
    const matchedBy =
      identity.email === email
        ? 'EMAIL'
        : identity.phoneNumber === phoneNumber
          ? 'PHONE'
          : 'UNKNOWN';
    const matchedValue =
      matchedBy === 'EMAIL'
        ? email
        : matchedBy === 'PHONE'
          ? phoneNumber
          : null;

    await this.prisma.accountIdentityReuseAudit.create({
      data: {
        accountId: account.id,
        previousAccountId: match.accountId,
        previousDeletionAuditId: match.id,
        matchedBy,
        matchedValue,
      },
    });
  }

  private resolveAccountDeletionChannel(
    account: Account,
    preferred?: AccountDeletionChannel,
  ) {
    if (preferred === AccountDeletionChannel.EMAIL) {
      if (!account.email) {
        throw new BadRequestException('No hay correo disponible');
      }
      return AccountDeletionChannel.EMAIL;
    }
    if (preferred === AccountDeletionChannel.WHATSAPP) {
      if (!account.phoneNumber) {
        throw new BadRequestException('No hay WhatsApp disponible');
      }
      return AccountDeletionChannel.WHATSAPP;
    }
    if (account.email) {
      return AccountDeletionChannel.EMAIL;
    }
    if (account.phoneNumber) {
      return AccountDeletionChannel.WHATSAPP;
    }
    throw new BadRequestException('No hay canal de verificacion disponible');
  }

  private resolvePhoneChangeChannel(
    account: Account,
    preferred?: AccountVerificationChannel,
  ) {
    if (preferred === AccountVerificationChannel.EMAIL) {
      if (!account.email) {
        throw new BadRequestException('No hay correo disponible');
      }
      return AccountVerificationChannel.EMAIL;
    }
    if (preferred === AccountVerificationChannel.WHATSAPP) {
      if (!account.phoneNumber) {
        throw new BadRequestException('No hay WhatsApp disponible');
      }
      return AccountVerificationChannel.WHATSAPP;
    }
    if (account.email) {
      return AccountVerificationChannel.EMAIL;
    }
    if (account.phoneNumber) {
      return AccountVerificationChannel.WHATSAPP;
    }
    throw new BadRequestException('No hay canal de verificacion disponible');
  }

  private maskDestination(
    channel: AccountDeletionChannel | AccountVerificationChannel,
    destination: string,
  ) {
    if (String(channel) === 'EMAIL') {
      const [local, domain] = destination.split('@');
      const visibleLocal = local.length <= 2 ? `${local[0] ?? '*'}*` : `${local.slice(0, 2)}***`;
      return `${visibleLocal}@${domain ?? ''}`;
    }
    const digits = destination.replace(/[^\d+]/g, '');
    if (digits.length <= 4) return '***';
    return `${digits.slice(0, 3)}***${digits.slice(-2)}`;
  }

  private extractClientIp(meta?: RequestMeta) {
    const forwarded = meta?.forwardedFor?.split(',')[0]?.trim();
    if (forwarded) return forwarded;
    return meta?.ip ?? null;
  }

  private async runDeletionStep(
    service: string,
    operation: () => Promise<Record<string, number>>,
  ): Promise<DeletionOperationLog> {
    try {
      const operations = await operation();
      return { service, ok: true, operations };
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Error desconocido';
      this.logger.error(`Error limpiando datos en ${service}: ${message}`);
      return { service, ok: false, error: message };
    }
  }

  private async executeAccountDeletion(
    account: Account,
    channel: AccountDeletionChannel,
    meta?: RequestMeta,
  ) {
    const logs: DeletionOperationLog[] = [];
    const doctorId = account.doctorId ?? (account.role === AccountRole.DOCTOR ? account.subjectId ?? null : null);
    const patientId = account.role === AccountRole.PATIENT ? account.subjectId ?? null : null;
    const deletedAt = new Date();
    const identitySnapshot = await this.buildIdentitySnapshot(account, doctorId, patientId);

    logs.push(
      await this.runDeletionStep('auth', async () => {
        const randomSalt = randomBytes(24).toString('hex');
        const randomPassword = randomBytes(64).toString('hex');
        const randomHash = await argon2.hash(randomPassword + randomSalt, {
          type: argon2.argon2id,
        });

        const refreshTokens = Number(
          await this.prisma.$executeRaw`DELETE FROM "RefreshToken" WHERE "accountId" = ${account.id}`,
        );
        const twoFactorChallenges = Number(
          await this.prisma.$executeRaw`DELETE FROM "TwoFactorChallenge" WHERE "accountId" = ${account.id}`,
        );
        const recoveries = Number(
          await this.prisma.$executeRaw`DELETE FROM "PasswordRecovery" WHERE "accountId" = ${account.id}`,
        );
        const oauthCodes = Number(
          await this.prisma.$executeRaw`DELETE FROM "OAuthAuthorizationCode" WHERE "accountId" = ${account.id}`,
        );
        const collaboratorAgendas = Number(
          await this.prisma.$executeRaw`
            DELETE FROM "CollaboratorAgenda"
            WHERE "collaboratorId" IN (
              SELECT "id" FROM "Collaborator" WHERE "accountId" = ${account.id}
            )
          `,
        );
        const collaboratorPermissions = Number(
          await this.prisma.$executeRaw`
            DELETE FROM "CollaboratorPermission"
            WHERE "collaboratorId" IN (
              SELECT "id" FROM "Collaborator" WHERE "accountId" = ${account.id}
            )
          `,
        );
        const collaborators = Number(
          await this.prisma.$executeRaw`DELETE FROM "Collaborator" WHERE "accountId" = ${account.id}`,
        );
        const clinicAdmins = Number(
          await this.prisma.$executeRaw`DELETE FROM "ClinicAdmin" WHERE "accountId" = ${account.id}`,
        );
        const deletedEmail = `deleted+${account.id}+${randomUUID()}@meusalud.local`;
        const accountUpdated = Number(
          await this.prisma.$executeRaw`
            UPDATE "Account"
            SET
              "status" = CAST('LOCKED' AS "AccountStatus"),
              "passwordHash" = ${randomHash},
              "salt" = ${randomSalt},
              "email" = ${deletedEmail},
              "phoneNumber" = NULL,
              "twoFactorEnabled" = FALSE,
              "twoFactorSecret" = NULL,
              "pendingTwoFactorSecret" = NULL,
              "deletedAt" = ${deletedAt},
              "updatedAt" = ${deletedAt}
            WHERE "id" = ${account.id}
          `,
        );
        return {
          refreshTokens,
          twoFactorChallenges,
          recoveries,
          oauthCodes,
          collaboratorAgendas,
          collaboratorPermissions,
          collaborators,
          clinicAdmins,
          accountUpdated,
        };
      }),
    );

    if (patientId) {
      logs.push(
        await this.runDeletionStep('users', async () => {
          const owners = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientOwner" WHERE "patientId" = ${patientId}`,
          );
          const blocks = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientDoctorBlock" WHERE "patientId" = ${patientId}`,
          );
          const doctorNotes = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientDoctorNote" WHERE "patientId" = ${patientId}`,
          );
          const insurers = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientInsurer" WHERE "patientId" = ${patientId}`,
          );
          const contacts = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientContact" WHERE "patientId" = ${patientId}`,
          );
          const addresses = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientAddress" WHERE "patientId" = ${patientId}`,
          );
          const preference = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientPreference" WHERE "patientId" = ${patientId}`,
          );
          const patientUpdated = Number(
            await this.prisma.$executeRaw`
              UPDATE "users"."Patient"
              SET
                "ownerPatientId" = NULL,
                "gender" = NULL,
                "birthDate" = NULL,
                "documentType" = NULL,
                "documentNumber" = NULL,
                "patientType" = CAST('NONE' AS "users"."PatientType"),
                "insuranceName" = NULL,
                "insuranceCard" = NULL,
                "dataController" = NULL,
                "birthCity" = NULL,
                "birthProvince" = NULL,
                "nationalityCountryId" = NULL,
                "religion" = NULL,
                "maritalStatusId" = NULL,
                "educationId" = NULL,
                "notes" = NULL,
                "allergies" = NULL,
                "medication" = NULL,
                "medicalHistory" = NULL,
                "otherInfo" = NULL,
                "profileImageId" = NULL,
                "isDependent" = FALSE,
                "updatedAt" = ${deletedAt}
              WHERE "id" = ${patientId}
            `,
          );
          return {
            owners,
            blocks,
            doctorNotes,
            insurers,
            contacts,
            addresses,
            preference,
            patientUpdated,
          };
        }),
      );
    }

    if (doctorId) {
      logs.push(
        await this.runDeletionStep('users-doctor-links', async () => {
          const owners = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientOwner" WHERE "doctorId" = ${doctorId}`,
          );
          const blocks = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientDoctorBlock" WHERE "doctorId" = ${doctorId}`,
          );
          const doctorNotes = Number(
            await this.prisma.$executeRaw`DELETE FROM "users"."PatientDoctorNote" WHERE "doctorId" = ${doctorId}`,
          );
          return { owners, blocks, doctorNotes };
        }),
      );

      logs.push(
        await this.runDeletionStep('doctors', async () => {
          const specialties = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorSpecialty" WHERE "doctorId" = ${doctorId}`,
          );
          const diseases = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorDisease" WHERE "doctorId" = ${doctorId}`,
          );
          const locationPaymentMethods = Number(
            await this.prisma.$executeRaw`
              DELETE FROM "doctors"."DoctorLocationPaymentMethod"
              WHERE "locationId" IN (
                SELECT "id" FROM "doctors"."DoctorLocation" WHERE "doctorId" = ${doctorId}
              )
            `,
          );
          const locationNews = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorLocationNews" WHERE "doctorId" = ${doctorId}`,
          );
          const locations = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorLocation" WHERE "doctorId" = ${doctorId}`,
          );
          const preference = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorPreference" WHERE "doctorId" = ${doctorId}`,
          );
          const media = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorMedia" WHERE "doctorId" = ${doctorId}`,
          );
          const experienceItems = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorExperienceItem" WHERE "doctorId" = ${doctorId}`,
          );
          const languages = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorLanguage" WHERE "doctorId" = ${doctorId}`,
          );
          const certificates = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorCertificate" WHERE "doctorId" = ${doctorId}`,
          );
          const socialLinks = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorSocialLinks" WHERE "doctorId" = ${doctorId}`,
          );
          const bookingInfo = Number(
            await this.prisma.$executeRaw`DELETE FROM "doctors"."DoctorBookingInfo" WHERE "doctorId" = ${doctorId}`,
          );
          const doctorUpdated = Number(
            await this.prisma.$executeRaw`
              UPDATE "doctors"."Doctor"
              SET
                "email" = NULL,
                "phoneNumber" = NULL,
                "documentNumber" = NULL,
                "legalDocumentType" = NULL,
                "licenseNumbers" = CAST('{}' AS TEXT[]),
                "birthCity" = NULL,
                "birthProvince" = NULL,
                "nationality" = NULL,
                "bio" = NULL,
                "profileImageId" = NULL,
                "gender" = NULL,
                "rethusVerified" = FALSE,
                "status" = CAST('INACTIVE' AS "doctors"."DoctorStatus"),
                "reviewsCount" = 0,
                "reviewsAverage" = 0,
                "updatedAt" = ${deletedAt}
              WHERE "id" = ${doctorId}
            `,
          );
          return {
            specialties,
            diseases,
            locationPaymentMethods,
            locationNews,
            locations,
            preference,
            media,
            experienceItems,
            languages,
            certificates,
            socialLinks,
            bookingInfo,
            doctorUpdated,
          };
        }),
      );

      logs.push(
        await this.runDeletionStep('services', async () => {
          const preferences = Number(
            await this.prisma.$executeRaw`DELETE FROM "services"."ServiceColumnsPreference" WHERE "doctorId" = ${doctorId}`,
          );
          const services = Number(
            await this.prisma.$executeRaw`DELETE FROM "services"."Service" WHERE "doctorId" = ${doctorId}`,
          );
          return { preferences, services };
        }),
      );

      logs.push(
        await this.runDeletionStep('availability', async () => {
          const timeOff = Number(
            await this.prisma.$executeRaw`DELETE FROM "availability"."TimeOff" WHERE "doctorId" = ${doctorId}`,
          );
          const holidayOverrides = Number(
            await this.prisma.$executeRaw`DELETE FROM "availability"."HolidayOverride" WHERE "doctorId" = ${doctorId}`,
          );
          const rules = Number(
            await this.prisma.$executeRaw`DELETE FROM "availability"."WorkingHoursRule" WHERE "doctorId" = ${doctorId}`,
          );
          const policies = Number(
            await this.prisma.$executeRaw`DELETE FROM "availability"."BookingPolicy" WHERE "doctorId" = ${doctorId}`,
          );
          const agendas = Number(
            await this.prisma.$executeRaw`DELETE FROM "availability"."Agenda" WHERE "doctorId" = ${doctorId}`,
          );
          return { timeOff, holidayOverrides, rules, policies, agendas };
        }),
      );

      logs.push(
        await this.runDeletionStep('payments', async () => {
          const payments = Number(
            await this.prisma.$executeRaw`DELETE FROM "payments"."Payment" WHERE "doctorId" = ${doctorId}`,
          );
          return { payments };
        }),
      );

      logs.push(
        await this.runDeletionStep('subscriptions', async () => {
          const subscriptions = Number(
            await this.prisma.$executeRaw`DELETE FROM "subscriptions"."Subscription" WHERE "doctorId" = ${doctorId}`,
          );
          return { subscriptions };
        }),
      );

      logs.push(
        await this.runDeletionStep('templates', async () => {
          const templates = Number(
            await this.prisma.$executeRaw`DELETE FROM "templates"."Template" WHERE "doctorId" = ${doctorId}`,
          );
          return { templates };
        }),
      );
    }

    logs.push(
      await this.runDeletionStep('appointments', async () => {
        const episodeDocuments = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "appointments"."EpisodeDocument"
                WHERE ${patientId ? Prisma.sql`"patientId" = ${patientId} OR ` : Prisma.empty}
                  "doctorId" = ${doctorId}
              `,
            )
          : patientId
            ? Number(
                await this.prisma.$executeRaw`DELETE FROM "appointments"."EpisodeDocument" WHERE "patientId" = ${patientId}`,
              )
            : 0;
        const episodeAttachments = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "appointments"."EpisodeAttachment"
                WHERE ${patientId ? Prisma.sql`"patientId" = ${patientId} OR ` : Prisma.empty}
                  "doctorId" = ${doctorId}
              `,
            )
          : patientId
            ? Number(
                await this.prisma.$executeRaw`DELETE FROM "appointments"."EpisodeAttachment" WHERE "patientId" = ${patientId}`,
              )
            : 0;
        const episodes = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "appointments"."Episode"
                WHERE ${patientId ? Prisma.sql`"patientId" = ${patientId} OR ` : Prisma.empty}
                  "doctorId" = ${doctorId}
              `,
            )
          : patientId
            ? Number(
                await this.prisma.$executeRaw`DELETE FROM "appointments"."Episode" WHERE "patientId" = ${patientId}`,
              )
            : 0;
        const patientAttachments = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "appointments"."PatientAttachment"
                WHERE ${patientId ? Prisma.sql`"patientId" = ${patientId} OR ` : Prisma.empty}
                  "doctorId" = ${doctorId}
              `,
            )
          : patientId
            ? Number(
                await this.prisma.$executeRaw`DELETE FROM "appointments"."PatientAttachment" WHERE "patientId" = ${patientId}`,
              )
            : 0;
        const appointments = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "appointments"."Appointment"
                WHERE ${patientId ? Prisma.sql`"patientId" = ${patientId} OR ` : Prisma.empty}
                  "doctorId" = ${doctorId}
              `,
            )
          : patientId
            ? Number(
                await this.prisma.$executeRaw`DELETE FROM "appointments"."Appointment" WHERE "patientId" = ${patientId}`,
              )
            : 0;
        const series = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "appointments"."AppointmentSeries"
                WHERE ${patientId ? Prisma.sql`"patientId" = ${patientId} OR ` : Prisma.empty}
                  "doctorId" = ${doctorId}
              `,
            )
          : patientId
            ? Number(
                await this.prisma.$executeRaw`DELETE FROM "appointments"."AppointmentSeries" WHERE "patientId" = ${patientId}`,
              )
            : 0;
        return {
          episodeDocuments,
          episodeAttachments,
          episodes,
          patientAttachments,
          appointments,
          series,
        };
      }),
    );

    logs.push(
      await this.runDeletionStep('analytics', async () => {
        const dimOwnership = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "analytics"."DimDoctorPatientOwnership"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const factAppointments = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "analytics"."FactAppointment"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const factPayments = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "analytics"."FactPaymentTransaction"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const factReviews = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "analytics"."FactReview"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const feedback = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "analytics"."FactBookingFeedback"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const dimServices = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "analytics"."DimService" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const presence = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "analytics"."AggDoctorPresenceDaily" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const series = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "analytics"."AggSeries" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const messageMetrics = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "analytics"."DoctorMessageMetric" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const conversationStatus = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "analytics"."ConversationMessageStatus"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const dimDoctor = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "analytics"."DimDoctor" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        return {
          dimOwnership,
          factAppointments,
          factPayments,
          factReviews,
          feedback,
          dimServices,
          presence,
          series,
          messageMetrics,
          conversationStatus,
          dimDoctor,
        };
      }),
    );

    logs.push(
      await this.runDeletionStep('reminders', async () => {
        const reminders = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "reminders"."Reminder"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        return { reminders };
      }),
    );

    logs.push(
      await this.runDeletionStep('messages', async () => {
        const blocks = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "messages"."MessageBlock"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        const conversations = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "messages"."Conversation"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        return { blocks, conversations };
      }),
    );

    logs.push(
      await this.runDeletionStep('reviews', async () => {
        const reviews = doctorId || patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "reviews"."Review"
                WHERE ${doctorId ? Prisma.sql`"doctorId" = ${doctorId}` : Prisma.sql`FALSE`}
                  ${patientId ? Prisma.sql` OR "patientId" = ${patientId}` : Prisma.empty}
              `,
            )
          : 0;
        return { reviews };
      }),
    );

    logs.push(
      await this.runDeletionStep('clinics', async () => {
        const memberships = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "ClinicDoctorMembership" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const invites = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "ClinicDoctorInvite" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const agendaAssignments = doctorId
          ? Number(
              await this.prisma.$executeRaw`DELETE FROM "ClinicAgendaAssignment" WHERE "doctorId" = ${doctorId}`,
            )
          : 0;
        const agendaSlots = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                UPDATE "ClinicLocationAgendaSlot"
                SET "assignedDoctorId" = NULL, "assignedAgendaId" = NULL, "status" = CAST('OPEN' AS "ClinicAgendaSlotStatus")
                WHERE "assignedDoctorId" = ${doctorId}
              `,
            )
          : 0;
        return { memberships, invites, agendaAssignments, agendaSlots };
      }),
    );

    if (account.role === AccountRole.DOCTOR || account.role === AccountRole.PATIENT) {
      const subjectType =
        account.role === AccountRole.DOCTOR ? 'DOCTOR' : 'PATIENT';
      const subjectId = account.role === AccountRole.DOCTOR ? doctorId : patientId;
      if (subjectId) {
        logs.push(
          await this.runDeletionStep('consents', async () => {
            const consents = Number(
              await this.prisma.$executeRaw`
                DELETE FROM "consents"."Consent"
                WHERE "subjectType" = CAST(${subjectType} AS "consents"."SubjectType")
                  AND "subjectId" = ${subjectId}
              `,
            );
            const deletionTasks = Number(
              await this.prisma.$executeRaw`
                DELETE FROM "consents"."DeletionTask"
                WHERE "deletionRequestId" IN (
                  SELECT "id" FROM "consents"."DataDeletionRequest"
                  WHERE "subjectType" = CAST(${subjectType} AS "consents"."SubjectType")
                    AND "subjectId" = ${subjectId}
                )
              `,
            );
            const deletionRequests = Number(
              await this.prisma.$executeRaw`
                DELETE FROM "consents"."DataDeletionRequest"
                WHERE "subjectType" = CAST(${subjectType} AS "consents"."SubjectType")
                  AND "subjectId" = ${subjectId}
              `,
            );
            return { consents, deletionTasks, deletionRequests };
          }),
        );
      }
    }

    logs.push(
      await this.runDeletionStep('images', async () => {
        const doctorImages = doctorId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "images"."ImageAsset"
                WHERE "ownerType" = CAST('DOCTOR' AS "images"."OwnerType")
                  AND "ownerId" = ${doctorId}
              `,
            )
          : 0;
        const patientImages = patientId
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "images"."ImageAsset"
                WHERE "ownerType" = CAST('PATIENT' AS "images"."OwnerType")
                  AND "ownerId" = ${patientId}
              `,
            )
          : 0;
        return { doctorImages, patientImages };
      }),
    );

    logs.push(
      await this.runDeletionStep('communication', async () => {
        const normalizedEmail = account.email.toLowerCase();
        const notificationByEmail = Number(
          await this.prisma.$executeRaw`
            DELETE FROM "notification"."notification_log"
            WHERE lower("destination") = ${normalizedEmail}
              OR lower("normalizedDestination") = ${normalizedEmail}
          `,
        );
        const outboxByPhone = account.phoneNumber
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "notification"."message_outbox"
                WHERE "to_e164" = ${account.phoneNumber}
              `,
            )
          : 0;
        const leadsByPhone = account.phoneNumber
          ? Number(
              await this.prisma.$executeRaw`
                DELETE FROM "notification"."lead_capture"
                WHERE "phone" = ${account.phoneNumber}
              `,
            )
          : 0;
        return { notificationByEmail, outboxByPhone, leadsByPhone };
      }),
    );

    const failed = logs.filter((item) => !item.ok);
    const successful = logs.filter((item) => item.ok);
    const status =
      failed.length === 0
        ? AccountDeletionAuditStatus.COMPLETED
        : successful.length > 0
          ? AccountDeletionAuditStatus.PARTIAL
          : AccountDeletionAuditStatus.FAILED;
    const error =
      failed.length > 0
        ? failed.map((item) => `${item.service}: ${item.error}`).join(' | ')
        : null;

    await this.prisma.accountDeletionAudit.create({
      data: {
        accountId: account.id,
        role: account.role,
        channel,
        status,
        requestIp: this.extractClientIp(meta),
        requestUserAgent: meta?.userAgent ?? null,
        requestedAt: deletedAt,
        deletedAt,
        detailsJson: {
          identity: identitySnapshot,
          logs,
        },
        error,
      },
    });

    return {
      status,
      deletedAt,
      logs,
      error,
    };
  }

  async adminListAccounts(query: { page?: number; limit?: number; role?: string; q?: string }) {
    const page = Math.max(1, Number(query.page ?? 1));
    const limit = Math.min(Math.max(Number(query.limit ?? 20), 1), 100);
    const skip = (page - 1) * limit;
    const role = query.role?.toUpperCase()?.trim() || '';
    const q = query.q?.trim() || '';

    const where: Prisma.AccountWhereInput = {
      deletedAt: null,
    };

    if (role) {
      if (Object.values(AccountRole).includes(role as AccountRole)) {
        where.role = role as AccountRole;
      }
    }

    if (q) {
      where.OR = [
        { email: { contains: q, mode: 'insensitive' } },
        { phoneNumber: { contains: q } },
        { id: { equals: q } },
        { doctorId: { equals: q } },
        { subjectId: { equals: q } },
      ];
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.account.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          email: true,
          phoneNumber: true,
          role: true,
          status: true,
          subjectId: true,
          doctorId: true,
          createdAt: true,
          updatedAt: true,
          deletedAt: true,
        },
      }),
      this.prisma.account.count({ where }),
    ]);

    return {
      items,
      page,
      limit,
      total,
    };
  }

  async adminGetAccount(id: string) {
    const account = await this.prisma.account.findUnique({
      where: { id },
      select: {
        id: true,
        email: true,
        phoneNumber: true,
        role: true,
        status: true,
        subjectId: true,
        doctorId: true,
        onboardingStatus: true,
        twoFactorEnabled: true,
        createdAt: true,
        updatedAt: true,
        deletedAt: true,
      },
    });

    if (!account) {
      throw new NotFoundException('Cuenta no encontrada');
    }

    return account;
  }

  async adminUpdateAccount(id: string, dto: { email?: string; phoneNumber?: string }) {
    const account = await this.prisma.account.findUnique({ where: { id } });
    if (!account) {
      throw new NotFoundException('Cuenta no encontrada');
    }
    if (account.deletedAt) {
      throw new BadRequestException('Cuenta eliminada');
    }

    const nextEmail = dto.email?.trim().toLowerCase();
    const nextPhone = dto.phoneNumber?.trim() || null;

    if (nextEmail && nextEmail !== account.email.toLowerCase()) {
      const existing = await this.prisma.account.findUnique({ where: { email: nextEmail } });
      if (existing && existing.id !== account.id) {
        throw new ConflictException('El correo ya esta en uso');
      }
    }

    if (nextPhone && nextPhone !== account.phoneNumber) {
      const existing = await this.prisma.account.findUnique({ where: { phoneNumber: nextPhone } });
      if (existing && existing.id !== account.id) {
        throw new ConflictException('El telefono ya esta en uso');
      }
    }

    const updated = await this.prisma.account.update({
      where: { id },
      data: {
        email: nextEmail ?? account.email,
        phoneNumber: nextPhone || null,
      },
      select: {
        id: true,
        email: true,
        phoneNumber: true,
        role: true,
        status: true,
        subjectId: true,
        doctorId: true,
        onboardingStatus: true,
        twoFactorEnabled: true,
        createdAt: true,
        updatedAt: true,
        deletedAt: true,
      },
    });

    return updated;
  }

  async adminDeleteAccount(
    id: string,
    dto: { confirmEmail: string },
    requesterId: string | null,
    meta?: RequestMeta,
  ) {
    const account = await this.prisma.account.findUnique({ where: { id } });
    if (!account) {
      throw new NotFoundException('Cuenta no encontrada');
    }
    if (account.deletedAt) {
      throw new BadRequestException('Cuenta eliminada');
    }
    if (requesterId && account.id === requesterId) {
      throw new BadRequestException('No puedes eliminar tu propia cuenta');
    }

    const normalizedConfirm = dto.confirmEmail.trim().toLowerCase();
    if (normalizedConfirm !== account.email.toLowerCase()) {
      throw new BadRequestException('El correo no coincide');
    }

    return this.executeAccountDeletion(account, AccountDeletionChannel.EMAIL, meta);
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  private async publishUserRegisteredEvent(
    account: Account,
    profile?: { firstName?: string; lastName?: string; companyName?: string; taxId?: string },
  ) {
    if (
      account.role !== AccountRole.PATIENT &&
      account.role !== AccountRole.DOCTOR &&
      account.role !== AccountRole.CLINIC &&
      account.role !== AccountRole.EMPLOYER
    ) {
      return;
    }

    const firstName = profile?.firstName?.trim();
    const lastName = profile?.lastName?.trim();
    const companyName = profile?.companyName?.trim();
    const taxId = profile?.taxId?.trim();

    const payload = {
      authUserId: account.id,
      role: account.role,
      doctorId: account.doctorId ?? undefined,
      employerId: account.employerId ?? undefined,
      email: account.email,
      phoneNumber: account.phoneNumber ?? undefined,
      firstName: firstName || undefined,
      lastName: lastName || undefined,
      companyName: companyName || undefined,
      taxId: taxId || undefined,
    };

    this.logger.log(
      `[auth.user_registered] publish -> ${JSON.stringify(payload)}`,
    );

    await this.rabbitmq.publishAuthEvent({
      type: 'AuthUserRegistered',
      routingKey: 'auth.user_registered',
      data: payload,
    });
  }

  private parseRole(roleInput?: string): AccountRole {
    if (
      roleInput === AccountRole.PATIENT ||
      roleInput === AccountRole.DOCTOR ||
      roleInput === AccountRole.CLINIC ||
      roleInput === AccountRole.EMPLOYER
    ) {
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

  private createOAuthState(
    payload: { role: AccountRole; redirect?: string },
    ttlSeconds: number,
    provider: 'google' | 'apple',
  ) {
    return sign(
      {
        role: payload.role,
        redirect: payload.redirect ?? undefined,
        provider,
      },
      this.privateKey,
      {
        algorithm: 'RS256',
        expiresIn: ttlSeconds,
        keyid: 'meusalud-auth',
        issuer: 'meusalud-auth',
        audience: `${provider}-oauth-state`,
      },
    );
  }

  private verifyOAuthState(state: string, provider: 'google' | 'apple') {
    try {
      const decoded = verify(state, this.publicKey, {
        algorithms: ['RS256'],
        issuer: 'meusalud-auth',
        audience: `${provider}-oauth-state`,
      }) as { role?: AccountRole; redirect?: string; provider?: string };
      if (!decoded?.role || decoded.provider !== provider) {
        throw new UnauthorizedException('OAuth state invÃ¡lido');
      }
      return { role: decoded.role, redirect: decoded.redirect };
    } catch (error) {
      if (error instanceof TokenExpiredError) {
        throw new UnauthorizedException('OAuth state expirado');
      }
      throw new UnauthorizedException('OAuth state invÃ¡lido');
    }
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

  private buildRecoveryLink(baseUrl: string, token: string) {
    const trimmed = baseUrl.trim();
    if (!trimmed) {
      return `/recover?token=${encodeURIComponent(token)}`;
    }
    const hashIndex = trimmed.indexOf('#');
    const basePart = hashIndex >= 0 ? trimmed.slice(0, hashIndex) : trimmed;
    const hashPart = hashIndex >= 0 ? trimmed.slice(hashIndex) : '';
    const separator = basePart.includes('?') ? '&' : '?';
    return `${basePart}${separator}token=${encodeURIComponent(token)}${hashPart}`;
  }

  private async createPatientForAccount(account: Account, firstName: string, lastName: string) {
    const fullName = `${firstName} ${lastName}`.trim();
    const response = await fetch(`${this.usersBaseUrl.replace(/\/$/, '')}/patients`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-role': 'SYSTEM',
        'x-auth-user-id': account.id,
      },
      body: JSON.stringify({
        authUserId: account.id,
        firstGivenName: firstName,
        firstFamilyName: lastName,
        fullName,
        contact: {
          email: account.email,
          phoneE164: account.phoneNumber ?? undefined,
          isPrimary: true,
        },
      }),
    });

    if (!response.ok) {
      const body = await response.text();
      this.logger.error(`No se pudo crear paciente (status ${response.status}): ${body}`);
      throw new ServiceUnavailableException('No se pudo crear el paciente');
    }

    const data = (await response.json()) as { id?: string };
    if (!data?.id) {
      throw new ServiceUnavailableException('Respuesta invalida al crear paciente');
    }
    return data.id;
  }

  private inferPatientNameFromEmail(email: string) {
    const raw = email.split('@')[0] ?? '';
    const normalized = raw.replace(/[._-]+/g, ' ').trim();
    const chunks = normalized.split(/\s+/).filter(Boolean);
    const first = (chunks[0] ?? 'Paciente').slice(0, 40);
    const rest = chunks.slice(1).join(' ').slice(0, 60);
    return {
      firstName: this.capitalizeName(first),
      lastName: this.capitalizeName(rest || 'MeuSalud'),
    };
  }

  private capitalizeName(value: string) {
    return value
      .split(/\s+/)
      .filter(Boolean)
      .map((chunk) => chunk.charAt(0).toUpperCase() + chunk.slice(1))
      .join(' ');
  }

  private async findPatientIdByAuthUserId(authUserId: string) {
    const patientId = await this.tryFindPatientIdByAuthUserId(authUserId);
    if (!patientId) {
      throw new ServiceUnavailableException('No se pudo validar el perfil de paciente');
    }
    return patientId;
  }

  private async tryFindPatientIdByAuthUserId(authUserId: string): Promise<string | null> {
    try {
      const response = await fetch(
        `${this.usersBaseUrl.replace(/\/$/, '')}/patients/internal/by-auth-user/${encodeURIComponent(authUserId)}`,
        {
          headers: {
            'x-role': 'SYSTEM',
          },
        },
      );
      if (!response.ok) {
        return null;
      }
      const data = (await response.json()) as { patientId?: string | null };
      return data?.patientId ?? null;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`No se pudo consultar paciente por authUserId: ${message}`);
      return null;
    }
  }

  /**
   * Invitación empleado afiliado: no reutilizar pacientes ajenos encontrados solo por teléfono.
   */
  private async resolvePatientForAffiliateInvite(
    account: Account,
    firstName: string,
    lastName: string,
  ): Promise<string> {
    const existingByAuth = await this.tryFindPatientIdByAuthUserId(account.id);
    if (existingByAuth) {
      return existingByAuth;
    }

    const profile = await this.prisma.accountRoleProfile.findUnique({
      where: {
        accountId_role: {
          accountId: account.id,
          role: AccountRole.PATIENT,
        },
      },
      select: { subjectId: true },
    });
    if (profile?.subjectId) {
      await this.linkAuthUserToPatient({
        patientId: profile.subjectId,
        authUserId: account.id,
        email: account.email,
        phoneNumber: account.phoneNumber ?? undefined,
      });
      return profile.subjectId;
    }

    return this.createPatientForAccount(account, firstName, lastName);
  }

  private async linkOrCreatePatientForAccount(account: Account, firstName: string, lastName: string) {
    const existing = await this.findPatientByContact(account.email, account.phoneNumber ?? undefined);
    if (existing?.patientId) {
      const existingAuthUserId = existing.authUserId;
      if (existingAuthUserId) {
        const linkedAccount = await this.prisma.account.findUnique({ where: { id: existingAuthUserId } });
        if (linkedAccount && linkedAccount.id !== account.id) {
          throw new ConflictException('El paciente ya tiene una cuenta vinculada');
        }
      }
      await this.linkAuthUserToPatient({
        patientId: existing.patientId,
        authUserId: account.id,
        expectedAuthUserId: existingAuthUserId ?? undefined,
        email: account.email,
        phoneNumber: account.phoneNumber ?? undefined,
      });
      return existing.patientId;
    }
    return this.createPatientForAccount(account, firstName, lastName);
  }

  private async findPatientByContact(email: string, phoneNumber?: string) {
    const base = this.usersBaseUrl.replace(/\/$/, '');
    const headers = { 'x-role': 'SYSTEM' };
    if (phoneNumber) {
      try {
        const response = await fetch(`${base}/patients/search?phone=${encodeURIComponent(phoneNumber)}`, { headers });
        if (response.ok) {
          const data = (await response.json()) as { items?: Array<{ id: string; authUserId?: string | null; contacts?: Array<{ email?: string | null }> }> };
          const lowerEmail = email.toLowerCase();
          const emailMatch = data.items?.find((item) =>
            item.contacts?.some((contact) => (contact.email ?? '').toLowerCase() === lowerEmail),
          );
          const match = emailMatch ?? data.items?.[0];
          if (match?.id) {
            if (emailMatch) {
              return { patientId: match.id, authUserId: match.authUserId ?? null };
            }
            // If phone matched but email doesn't, prefer email search below.
          }
        }
      } catch {
        // ignore and try email
      }
    }
    try {
      const response = await fetch(`${base}/patients/search?q=${encodeURIComponent(email)}`, { headers });
      if (!response.ok) return null;
      const data = (await response.json()) as { items?: Array<{ id: string; authUserId?: string | null; contacts?: Array<{ email?: string | null }> }> };
      const lower = email.toLowerCase();
      const match = data.items?.find((item) =>
        item.contacts?.some((contact) => (contact.email ?? '').toLowerCase() === lower),
      ) ?? data.items?.[0];
      if (!match?.id) return null;
      return { patientId: match.id, authUserId: match.authUserId ?? null };
    } catch {
      return null;
    }
  }

  private async linkAuthUserToPatient(input: {
    patientId: string;
    authUserId: string;
    expectedAuthUserId?: string;
    email?: string;
    phoneNumber?: string;
  }) {
    const base = this.usersBaseUrl.replace(/\/$/, '');
    const response = await fetch(`${base}/patients/internal/link-auth-user`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-role': 'SYSTEM',
      },
      body: JSON.stringify({
        patientId: input.patientId,
        authUserId: input.authUserId,
        expectedAuthUserId: input.expectedAuthUserId,
        email: input.email,
        phoneE164: input.phoneNumber,
      }),
    });
    if (!response.ok) {
      const body = await response.text();
      let message = body;
      try {
        const json = JSON.parse(body) as { message?: unknown };
        const parsed = json?.message;
        if (typeof parsed === 'string') message = parsed;
        else if (Array.isArray(parsed) && parsed.length) message = String(parsed[0]);
      } catch {
        // keep raw body
      }
      if (response.status === 400 || response.status === 422) {
        throw new BadRequestException(message || 'No se pudo vincular el paciente');
      }
      if (response.status === 409) {
        throw new ConflictException(message || 'El paciente ya tiene una cuenta vinculada');
      }
      this.logger.error(`link-auth-user failed (${response.status}): ${body}`);
      throw new ServiceUnavailableException(message || 'No se pudo vincular el paciente');
    }
  }

  private async resolveRecoveryName(account: Account) {
    if (account.role === AccountRole.PATIENT) {
      return this.resolvePatientName(account.id);
    }
    if (account.role === AccountRole.DOCTOR) {
      return this.resolveDoctorName(account.id);
    }
    if (account.role === AccountRole.CLINIC) {
      return this.resolveClinicName(account.id);
    }
    return 'Usuario MeuSalud';
  }

  private async ensureRecoveryProfile(account: Account) {
    if (account.role === AccountRole.DOCTOR) {
      const name = await this.resolveDoctorName(account.id);
      if (!name || name === 'Usuario MeuSalud') {
        throw new BadRequestException('No se encontro el perfil del doctor');
      }
    }
    if (account.role === AccountRole.CLINIC) {
      const name = await this.resolveClinicName(account.id);
      if (!name || name === 'Usuario MeuSalud') {
        throw new BadRequestException('No se encontro el perfil de la clinica');
      }
    }
  }

  private async resolvePatientName(authUserId: string) {
    try {
      const response = await fetch(
        `${this.usersBaseUrl.replace(/\/$/, '')}/patients/internal/by-auth-user/${encodeURIComponent(authUserId)}`,
        {
          headers: {
            'x-role': 'SYSTEM',
          },
        },
      );
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`No se pudo obtener nombre del paciente (status ${response.status}): ${body}`);
        return 'Usuario MeuSalud';
      }
      const data = (await response.json()) as {
        fullName?: string | null;
        firstName?: string | null;
        lastName?: string | null;
      };
      return this.composeName(data.fullName, data.firstName, data.lastName);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`No se pudo obtener nombre del paciente: ${message}`);
      return 'Usuario MeuSalud';
    }
  }

  private async resolveDoctorName(authUserId: string) {
    try {
      const response = await fetch(
        `${this.doctorsBaseUrl.replace(/\/$/, '')}/doctors/me?authUserId=${encodeURIComponent(authUserId)}`,
        {
          headers: {
            'x-role': 'SYSTEM',
          },
        },
      );
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`No se pudo obtener nombre del doctor (status ${response.status}): ${body}`);
        return 'Usuario MeuSalud';
      }
      const data = (await response.json()) as { fullName?: string | null };
      return (data.fullName?.trim() || 'Usuario MeuSalud');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`No se pudo obtener nombre del doctor: ${message}`);
      return 'Usuario MeuSalud';
    }
  }

  private async resolveClinicName(authUserId: string) {
    try {
      const response = await fetch(
        `${this.clinicsInternalBaseUrl.replace(/\/$/, '')}/clinics/me/default`,
        {
          headers: {
            'x-role': 'SYSTEM',
            'x-auth-user-id': authUserId,
          },
        },
      );
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`No se pudo obtener nombre de la clinica (status ${response.status}): ${body}`);
        return 'Usuario MeuSalud';
      }
      const data = (await response.json()) as { clinic?: { name?: string | null } | null };
      return (data.clinic?.name?.trim() || 'Usuario MeuSalud');
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`No se pudo obtener nombre de la clinica: ${message}`);
      return 'Usuario MeuSalud';
    }
  }

  private composeName(fullName?: string | null, firstName?: string | null, lastName?: string | null) {
    const safeFull = fullName?.trim();
    if (safeFull) {
      return safeFull;
    }
    const composed = [firstName, lastName]
      .map((value) => value?.trim() || '')
      .filter(Boolean)
      .join(' ')
      .trim();
    return composed || 'Usuario MeuSalud';
  }

  private async ensurePatientSubjectId(account: Account) {
    if (account.role !== AccountRole.PATIENT) {
      return account;
    }
    if (account.subjectId) {
      return account;
    }

    const patientId = await this.resolvePatientIdForSession(account);
    return this.prisma.account.update({
      where: { id: account.id },
      data: { subjectId: patientId },
    });
  }

  private normalizePhoneNumber(value: string) {
    const trimmed = value.replace(/[\s.-]/g, '');
    if (!trimmed.startsWith('+')) {
      return `+${trimmed}`;
    }
    return trimmed;
  }

  private resolveTwoFactorMethod(account: Account) {
    return account.twoFactorMethod ?? TwoFactorMethod.TOTP;
  }

  private async findAccountById(authUserId: string) {
    const account = await this.prisma.account.findUnique({
      where: { id: authUserId },
    });
    if (!account || account.status !== AccountStatus.ACTIVE) {
      throw new UnauthorizedException('Cuenta no disponible');
    }
    if (account.deletedAt) {
      throw new BadRequestException('La cuenta ya fue eliminada');
    }
    return account;
  }

  private async sendWhatsAppTwoFactorCode(
    account: Account,
    challenge: { plainCode?: string | null; destination?: string | null },
  ) {
    if (!challenge.destination || !challenge.plainCode || !account.phoneNumber) {
      throw new BadRequestException('No hay WhatsApp disponible');
    }
    const name = await this.resolveRecoveryName(account);
    await this.notifications.sendTwoFactorWhatsapp({
      phoneNumber: challenge.destination,
      name,
      code: challenge.plainCode,
      ttlSeconds: this.challengeTtl,
    });
  }

  private async createTwoFactorChallenge(
    account: Account,
    options?: {
      sessionRole?: AccountRole;
      method?: TwoFactorMethod;
      purpose?: TwoFactorChallengePurpose;
      destination?: string | null;
      generateCode?: boolean;
    },
  ) {
    const id = nanoid(48);
    const expiresAt = new Date(Date.now() + this.challengeTtl * 1000);
    const method = options?.method ?? this.resolveTwoFactorMethod(account);
    const code = options?.generateCode ? this.generateRecoveryCode() : null;
    const challenge = await this.prisma.twoFactorChallenge.create({
      data: {
        id,
        accountId: account.id,
        sessionRole: options?.sessionRole,
        method,
        purpose: options?.purpose ?? TwoFactorChallengePurpose.LOGIN,
        codeHash: code ? this.hashToken(code) : null,
        destination: options?.destination ?? null,
        expiresAt,
      },
    });
    return {
      ...challenge,
      plainCode: code,
    };
  }

  private async buildTwoFactorRequiredResponse(
    account: Account,
    options: {
      sessionRole?: AccountRole;
      availableRoles?: AccountRole[];
      availableProductAccess?: Awaited<ReturnType<AuthService['getAvailableProductAccess']>>;
    } = {},
  ) {
    const method = this.resolveTwoFactorMethod(account);
    const challenge = await this.createTwoFactorChallenge(account, {
      sessionRole: options.sessionRole,
      method,
      purpose: TwoFactorChallengePurpose.LOGIN,
      destination: method === TwoFactorMethod.WHATSAPP ? account.phoneNumber : null,
      generateCode: method === TwoFactorMethod.WHATSAPP,
    });
    if (method === TwoFactorMethod.WHATSAPP) {
      await this.sendWhatsAppTwoFactorCode(account, challenge);
    }
    return {
      requiresTwoFactor: true as const,
      challengeId: challenge.id,
      method,
      channel: method === TwoFactorMethod.WHATSAPP ? 'phone' as const : 'authenticator' as const,
      destinationMasked:
        method === TwoFactorMethod.WHATSAPP && challenge.destination
          ? this.maskDestination(AccountVerificationChannel.WHATSAPP, challenge.destination)
          : null,
      expiresAt: challenge.expiresAt.toISOString(),
      ...(options.availableRoles ? { availableRoles: options.availableRoles } : {}),
      ...(options.availableProductAccess ? { availableProductAccess: options.availableProductAccess } : {}),
    };
  }

  private async resolveSessionRole(account: Account, requestedRole?: AccountRole) {
    if (!requestedRole) {
      return account.role;
    }
    if (requestedRole === account.role) {
      return requestedRole;
    }
    // Verificar si el rol solicitado existe como perfil secundario
    const profile = await this.prisma.accountRoleProfile.findUnique({
      where: { accountId_role: { accountId: account.id, role: requestedRole } },
    });
    if (profile) {
      return requestedRole;
    }
    throw new BadRequestException('Rol no permitido para esta cuenta');
  }

  private async getAvailableRoles(account: Account): Promise<AccountRole[]> {
    const profiles = await this.prisma.accountRoleProfile.findMany({
      where: { accountId: account.id },
      select: { role: true },
    });
    const roles = new Set<AccountRole>([account.role, ...profiles.map((p) => p.role)]);
    return Array.from(roles);
  }

  private async getAvailableProductAccess(accountId: string) {
    return this.prisma.accountProductAccess.findMany({
      where: {
        accountId,
        status: { not: ProductAccessStatus.DISABLED },
      },
      orderBy: [{ product: 'asc' }, { role: 'asc' }],
    });
  }

  private async ensureProductAccess(
    accountId: string,
    product: ProductCode,
    role: ProductRole,
    subjectId?: string | null,
  ) {
    return this.prisma.accountProductAccess.upsert({
      where: {
        accountId_product_role: {
          accountId,
          product,
          role,
        },
      },
      create: {
        accountId,
        product,
        role,
        subjectId: subjectId ?? null,
        status: ProductAccessStatus.ACTIVE,
      },
      update: {
        subjectId: subjectId ?? undefined,
        status: ProductAccessStatus.ACTIVE,
      },
    });
  }

  private async ensureLegacyProductAccess(account: Account) {
    if (account.role === AccountRole.DOCTOR && account.doctorId) {
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_PRO, ProductRole.DOCTOR, account.doctorId);
    }
    if (account.role === AccountRole.CLINIC && account.subjectId) {
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_PRO, ProductRole.MEDICAL_ENTITY, account.subjectId);
    }
    if (account.role === AccountRole.EMPLOYER && account.employerId) {
      await this.ensureProductAccess(
        account.id,
        ProductCode.MEUDOC_EMPLOYER,
        ProductRole.EMPLOYER_ADMIN,
        account.employerId,
      );
    }
    if (account.role === AccountRole.ADMIN) {
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_ADMIN, ProductRole.ADMIN, null);
    }
    if (account.role === AccountRole.COMERCIAL) {
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_ADMIN, ProductRole.COMERCIAL, null);
    }
  }

  private async resolvePatientIdForSession(
    account: Account,
    sessionSubjectId?: string | null,
  ) {
    if (sessionSubjectId) {
      return sessionSubjectId;
    }
    if (account.role === AccountRole.PATIENT && account.subjectId) {
      return account.subjectId;
    }
    let patientId = await this.findPatientIdByAuthUserId(account.id);
    if (!patientId) {
      const inferredName = this.inferPatientNameFromEmail(account.email);
      patientId = await this.createPatientForAccount(
        account,
        inferredName.firstName,
        inferredName.lastName,
      );
    }
    return patientId;
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
      if (this.tokenDebug) {
        this.logger.warn({
          message: 'Refresh token invalid',
          found: Boolean(stored),
          now: new Date().toISOString(),
          expiresAt: stored?.expiresAt?.toISOString() ?? null,
          accountId: stored?.accountId ?? null,
          tokenHashPrefix: hash.slice(0, 10),
        });
      }
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
