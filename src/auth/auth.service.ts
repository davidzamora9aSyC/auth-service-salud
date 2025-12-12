import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Account, AccountStatus, TwoFactorMethod } from '@prisma/client';
import { readFileSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import * as argon2 from 'argon2';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { authenticator } from 'otplib';
import { sign, SignOptions } from 'jsonwebtoken';
import { nanoid } from 'nanoid';
import { TwoFactorSetupDto } from './dto/two-factor-setup.dto';
import { TwoFactorCodeDto } from './dto/two-factor-code.dto';

@Injectable()
export class AuthService {
  private readonly privateKey: Buffer;
  private readonly accessTtl: number;
  private readonly refreshTtl: number;
  private readonly challengeTtl: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {
    const privateKeyPath = this.config.get<string>('JWT_PRIVATE_KEY_PATH');
    if (!privateKeyPath) {
      throw new Error('JWT_PRIVATE_KEY_PATH is not configured');
    }
    this.privateKey = readFileSync(privateKeyPath);
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
  }

  async register(dto: RegisterDto) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const existing = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
    });
    if (existing) {
      throw new ConflictException('Email already registered');
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
        role: dto.role,
        subjectId: dto.subjectId ?? null,
      },
    });
    return {
      id: account.id,
      email: account.email,
      role: account.role,
      twoFactorEnabled: account.twoFactorEnabled,
    };
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

  private async issueTokens(account: Account) {
    const payload = {
      sub: account.id,
      role: account.role,
      subjectId: account.subjectId,
    };
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
      },
    };
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
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
