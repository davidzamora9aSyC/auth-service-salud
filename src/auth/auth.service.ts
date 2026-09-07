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
  AccountProductAccess,
  AccountRoleProfile,
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
  ReferralType,
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
import { RegistrationPrefillService } from './registration-prefill.service';
import { ReferralRegistrationInvitesService } from './referral-registration-invites.service';

type PatientAdminKpis = {
  accountId: string;
  doctorSearchCount: number;
  avgInteractionsPerTrackedSession: number | null;
  avgInteractionsPerTrackedSessionLast7Days: number | null;
  hasConsultation: boolean;
  appointmentCount: number;
  lastAppointmentAt: string | null;
};

type AccountLoginInsights = {
  loginCount: number;
  lastLoginAt: string | null;
};

type EmployerAdminSummary = {
  employerId: string;
  displayName: string | null;
  totalCareRequests: number;
  approvedCareRequests: number;
  appointmentCount: number;
  hasFirstPatientAppointment: boolean;
};

type RequestMeta = {
  ip?: string;
  forwardedFor?: string;
  userAgent?: string;
  requesterId?: string | null;
  requesterRole?: string | null;
};

type DeletionOperationLog = {
  service: string;
  ok: boolean;
  operations?: Record<string, number>;
  error?: string;
};

type AccountDeletionGrant = {
  product: ProductCode;
  role: ProductRole;
  subjectId: string | null;
  source: 'product-access' | 'role-profile' | 'legacy-account';
};

type ProductAccessContext = {
  id: string;
  product: ProductCode;
  role: ProductRole;
  subjectId?: string | null;
  status: ProductAccessStatus;
};

type ResolvedPatientPortalSession = {
  patientId: string;
  productAccess: ProductAccessContext;
};

type AuthRegistrationSessionContext = {
  patientId?: string | null;
  productAccess?: ProductAccessContext | null;
};

type SessionProductAccessInput = {
  sessionRole?: AccountRole;
  productAccess?: ProductAccessContext | null;
  activeProduct?: ProductCode | null;
  activeProductRole?: ProductRole | null;
  productSubjectId?: string | null;
};

type LoginProductIntent = {
  accountRole: AccountRole;
  product: ProductCode;
  productRoles: ProductRole[];
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
    private readonly registrationPrefill: RegistrationPrefillService,
    private readonly referralRegistrationInvites: ReferralRegistrationInvitesService,
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
      const referralInviteToken = dto.referralInviteToken?.trim();
      if (inviteToken && dto.role === AccountRole.EMPLOYER) {
        throw new BadRequestException(
          'Para unirte a una empresa existente usa el enlace de invitacion del portal empresa',
        );
      }
      if (inviteToken && dto.role !== AccountRole.DOCTOR) {
        throw new BadRequestException('inviteToken solo aplica para registro de medicos');
      }
      if (referralInviteToken && dto.role !== AccountRole.PATIENT && dto.role !== AccountRole.EMPLOYER) {
        throw new BadRequestException('referralInviteToken solo aplica para registro de pacientes o empresas');
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
      const referralInvite =
        referralInviteToken && (dto.role === AccountRole.PATIENT || dto.role === AccountRole.EMPLOYER)
          ? await this.referralRegistrationInvites.resolveInviteForRegister({
              token: referralInviteToken,
              role: dto.role === AccountRole.PATIENT ? ReferralType.PATIENT : ReferralType.COMPANY,
              email: normalizedEmail,
              phoneNumber: normalizedPhone,
              companyName: dto.companyName,
              taxId: dto.taxId,
            })
          : null;
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
      return this.addRoleToAccount(
        existing,
        dto,
        firstName,
        lastName,
        inviteToken,
        invite?.doctorId,
        isAdminInvite,
        referralInviteToken,
        referralInvite?.type ?? null,
      );
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
    const accountRole = dto.role === AccountRole.PATIENT ? AccountRole.MEMBER : dto.role;
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
          role: accountRole,
          subjectId: dto.role === AccountRole.PATIENT ? null : dto.subjectId ?? null,
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
    let sessionProductAccess: ProductAccessContext | null = null;
    if (dto.role === AccountRole.PATIENT) {
      if (!firstName || !lastName) {
        await this.prisma.account.delete({ where: { id: account.id } });
        throw new BadRequestException('Nombre y apellido son requeridos');
      }
      try {
        const patientAccess = await this.provisionPatientAccessForAccount(account, {
          firstName,
          lastName,
        });
        sessionProductAccess = patientAccess.productAccess;
      } catch (error) {
        await this.prisma.account.delete({ where: { id: account.id } }).catch(() => undefined);
        throw error;
      }
    }
      await this.publishUserRegisteredEvent(
        account,
        {
          firstName,
          lastName,
          companyName: dto.companyName,
          taxId: dto.taxId,
        },
        dto.role,
        dto.role === AccountRole.PATIENT && sessionProductAccess
          ? {
              patientId: sessionProductAccess.subjectId,
              productAccess: sessionProductAccess,
            }
          : undefined,
      );
      if (inviteToken && invite) {
        await this.adminOnboarding.markInviteAccepted(inviteToken, account.id);
      }
      if (referralInviteToken && referralInvite) {
        const acceptedSubjectId =
          dto.role === AccountRole.PATIENT
            ? sessionProductAccess?.subjectId
            : dto.role === AccountRole.EMPLOYER
              ? employerId
              : null;
        if (acceptedSubjectId) {
          await this.referralRegistrationInvites.markInviteAccepted(
            referralInviteToken,
            account.id,
            acceptedSubjectId,
          );
        }
      }
    await this.ensureLegacyProductAccess(account);
    await this.recordIdentityReuse(account, normalizedEmail, normalizedPhone);
    const tokens = await this.issueTokens(account, {
      sessionRole: dto.role,
      productAccess: sessionProductAccess ?? undefined,
    });
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
        productAccess,
        availableProductAccess,
      });
    }

    await this.registrationPrefill.ensureMeuredProfile(account.id, {
      firstName: dto.firstName,
      lastName: dto.lastName,
      productRole: dto.role,
    });

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
    referralInviteToken?: string,
    referralInviteType?: ReferralType | null,
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

    let sessionProductAccess: ProductAccessContext | null = null;
    if (dto.role === AccountRole.PATIENT) {
      if (!firstName || !lastName) {
        throw new BadRequestException('Nombre y apellido son requeridos');
      }
      const patientAccess = await this.provisionPatientAccessForAccount(account, {
        firstName,
        lastName,
      });
      sessionProductAccess = patientAccess.productAccess;
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
        }, dto.role);
        if (referralInviteToken && referralInviteType === ReferralType.COMPANY) {
          await this.referralRegistrationInvites.markInviteAccepted(
            referralInviteToken,
            account.id,
            employerId,
          );
        }
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
    // Los perfiles de doctor se materializan en doctors-service a partir de este
    // evento. Sin publicarlo, una cuenta existente que agrega el rol DOCTOR
    // recibe un JWT válido, pero su doctorId no existe en ese servicio.
    if (dto.role === AccountRole.DOCTOR) {
      await this.publishUserRegisteredEvent(updatedAccount, { firstName, lastName }, dto.role);
    }
    if (
      dto.role === AccountRole.PATIENT &&
      referralInviteToken &&
      referralInviteType === ReferralType.PATIENT &&
      sessionProductAccess?.subjectId
    ) {
      await this.referralRegistrationInvites.markInviteAccepted(
        referralInviteToken,
        updatedAccount.id,
        sessionProductAccess.subjectId,
      );
    }
    const availableRoles = await this.getAvailableRoles(updatedAccount);
    const availableProductAccess = await this.getAvailableProductAccess(updatedAccount.id);
    if (updatedAccount.twoFactorEnabled) {
      return this.buildTwoFactorRequiredResponse(updatedAccount, {
        sessionRole: dto.role,
        productAccess: sessionProductAccess ?? undefined,
        availableRoles,
        availableProductAccess,
      });
    }

    const tokens = await this.issueTokens(updatedAccount, {
      sessionRole: dto.role,
      productAccess: sessionProductAccess ?? undefined,
    });
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
    const productLoginContext = dto.role
      ? await this.resolveProductLoginContext(account, dto.role)
      : null;
    const sessionRole = productLoginContext?.sessionRole ?? await this.resolveSessionRole(account, dto.role);
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
    const sessionProductAccess = productLoginContext?.productAccess ?? null;
    const availableRoles = await this.getAvailableRoles(account);
    if (account.twoFactorEnabled) {
      return this.buildTwoFactorRequiredResponse(account, {
        sessionRole,
        productAccess: sessionProductAccess ?? undefined,
        availableRoles,
        availableProductAccess: await this.getAvailableProductAccess(account.id),
      });
    }
    const tokens = await this.issueTokens(account, {
      sessionRole,
      productAccess: sessionProductAccess ?? undefined,
    });
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
    if (!productAccess || productAccess.status !== ProductAccessStatus.ACTIVE) {
      throw new BadRequestException('Acceso de producto no disponible');
    }

    await this.assertProductAccessProfile(stored.account, productAccess);

    await this.prisma.refreshToken.delete({ where: { tokenHash } });
    const sessionRole = this.resolveSessionRoleForProductAccess(stored.account, productAccess);
    const tokens = await this.issueTokens(stored.account, {
      sessionRole,
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
    const existingHasPatientRole = existing
      ? await this.accountHasRole(existing, AccountRole.PATIENT)
      : false;
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
      if (existing.role !== AccountRole.COLLABORATOR && !existingHasPatientRole) {
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

      if (existingHasPatientRole) {
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
          role: AccountRole.MEMBER,
          phoneNumber: normalizedPhone,
          employerId: null,
          onboardingStatus: OnboardingStatus.COMPLETE,
        },
      });
      await this.recordIdentityReuse(created, normalizedEmail, normalizedPhone ?? '');
      return created;
    });

    const patientId = await this.linkOrCreatePatientForAccount(account, dto.firstName.trim(), dto.lastName.trim());
    await this.provisionPatientAccessForAccount(account, { patientId });

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

  async accountExistsByContact(input: { email?: string; phoneNumber?: string }) {
    const normalizedEmail = input.email?.trim().toLowerCase() || null;
    const normalizedPhone = input.phoneNumber
      ? this.normalizePhoneNumber(input.phoneNumber)
      : null;

    if (!normalizedEmail && !normalizedPhone) {
      throw new BadRequestException('Email or phoneNumber is required');
    }

    const existing = await this.prisma.account.findFirst({
      where: {
        status: AccountStatus.ACTIVE,
        OR: [
          normalizedEmail ? { email: normalizedEmail } : undefined,
          normalizedPhone ? { phoneNumber: normalizedPhone } : undefined,
        ].filter(Boolean) as Prisma.AccountWhereInput[],
      },
      select: { id: true },
    });

    return { exists: Boolean(existing) };
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

    await this.provisionPatientAccessForAccount(account, { patientId });

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
    const productAccess = await this.resolveSessionProductAccess(challenge.account, {
      sessionRole,
      activeProduct: challenge.activeProduct,
      activeProductRole: challenge.activeProductRole,
      productSubjectId: challenge.productSubjectId,
    });
    const tokens = await this.issueTokens(challenge.account, {
      sessionRole,
      productAccess: productAccess ?? undefined,
    });
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
    const stored = await this.findRefreshToken(refreshToken);
    await this.revokeRefreshToken(refreshToken);
    const productAccess = await this.resolveSessionProductAccess(stored.account, {
      sessionRole: stored.sessionRole ?? stored.account.role,
      activeProduct: stored.activeProduct,
      activeProductRole: stored.activeProductRole,
      productSubjectId: stored.productSubjectId,
    });
    const tokens = await this.issueTokens(stored.account, {
      sessionRole: stored.sessionRole ?? stored.account.role,
      sessionSubjectId: stored.sessionSubjectId ?? undefined,
      productAccess: productAccess ?? undefined,
    });
    const availableProductAccess = await this.getAvailableProductAccess(stored.account.id);
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
      {
        ...meta,
        requesterId: authUserId,
        requesterRole: challenge.account.role,
      },
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
    }) as {
      sub?: string;
      role?: string;
      activeProduct?: string;
      activeProductRole?: string;
      productSubjectId?: string;
    };
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
        sessionRole: this.parseAccountRole(payload.role),
        activeProduct: this.parseProductCode(payload.activeProduct),
        activeProductRole: this.parseProductRole(payload.activeProductRole),
        productSubjectId:
          typeof payload.productSubjectId === 'string' ? payload.productSubjectId : null,
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
      let sessionProductAccess: ProductAccessContext | null = null;
      let shouldPublishRegistrationEvent = false;
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
            role: entry.role === AccountRole.PATIENT ? AccountRole.MEMBER : entry.role,
            subjectId: entry.role === AccountRole.PATIENT ? null : profile.sub ?? null,
            phoneNumber: null,
            doctorId,
            employerId,
            onboardingStatus,
          },
        });
        shouldPublishRegistrationEvent = entry.role !== AccountRole.PATIENT;
      }
      if (entry.role === AccountRole.PATIENT) {
        const googleProfile = profile as { given_name?: string; family_name?: string };
        const patientAccess = await this.provisionPatientAccessForAccount(account, {
          firstName: googleProfile.given_name?.trim(),
          lastName: googleProfile.family_name?.trim(),
        });
        sessionProductAccess = patientAccess.productAccess;
        if (!existing) {
          await this.publishUserRegisteredEvent(
            account,
            {
              firstName: googleProfile.given_name?.trim(),
              lastName: googleProfile.family_name?.trim(),
              companyName: profile.name?.trim() || normalizedEmail.split('@')[0],
            },
            entry.role,
            {
              patientId: patientAccess.patientId,
              productAccess: patientAccess.productAccess,
            },
          );
        }
      } else if (shouldPublishRegistrationEvent) {
        await this.publishUserRegisteredEvent(
          account,
          {
            companyName: profile.name?.trim() || normalizedEmail.split('@')[0],
          },
          entry.role,
        );
      }

      const sessionRole =
        entry.role === AccountRole.PATIENT
          ? AccountRole.PATIENT
          : (existing && existing.role !== entry.role && allowRoleSwitchGoogle)
            ? entry.role
            : account.role;
      const tokens = await this.issueTokens(account, {
        sessionRole,
        productAccess: sessionProductAccess ?? undefined,
      });
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
    let sessionProductAccess: ProductAccessContext | null = null;
    let shouldPublishRegistrationEvent = false;
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
          role: entry.role === AccountRole.PATIENT ? AccountRole.MEMBER : entry.role,
          subjectId: entry.role === AccountRole.PATIENT ? null : decoded.sub ?? null,
          phoneNumber: null,
          doctorId,
          employerId,
          onboardingStatus,
        },
      });
      shouldPublishRegistrationEvent = entry.role !== AccountRole.PATIENT;
    }
    if (entry.role === AccountRole.PATIENT) {
      const patientAccess = await this.provisionPatientAccessForAccount(account);
      sessionProductAccess = patientAccess.productAccess;
      if (!existing) {
        await this.publishUserRegisteredEvent(
          account,
          {
            companyName: normalizedEmail.split('@')[0],
          },
          entry.role,
          {
            patientId: patientAccess.patientId,
            productAccess: patientAccess.productAccess,
          },
        );
      }
    } else if (shouldPublishRegistrationEvent) {
      await this.publishUserRegisteredEvent(
        account,
        {
          companyName: normalizedEmail.split('@')[0],
        },
        entry.role,
      );
    }

    const sessionRole =
      entry.role === AccountRole.PATIENT
        ? AccountRole.PATIENT
        : (existing && existing.role !== entry.role && allowRoleSwitchApple)
          ? entry.role
          : account.role;
    const tokens = await this.issueTokens(account, {
      sessionRole,
      productAccess: sessionProductAccess ?? undefined,
    });
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
    let emittedRole = sessionRole;
    let effectiveProductAccess = options?.productAccess ?? null;
    const payload: Record<string, unknown> = {
      sub: account.id,
      role: emittedRole,
    };
    if (
      sessionRole === AccountRole.PATIENT ||
      this.isPatientPortalProductAccess(effectiveProductAccess)
    ) {
      const patientSession = await this.resolvePatientPortalSession(account, effectiveProductAccess);
      emittedRole = AccountRole.MEMBER;
      effectiveProductAccess = patientSession.productAccess;
      sessionSubjectId = patientSession.patientId;
      payload.role = emittedRole;
      payload.patientId = patientSession.patientId;
      payload.subjectId = patientSession.patientId;
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
    if (effectiveProductAccess) {
      payload.activeProduct = effectiveProductAccess.product;
      payload.activeProductRole = effectiveProductAccess.role;
      if (effectiveProductAccess.id) {
        payload.productAccessId = effectiveProductAccess.id;
      }
      if (effectiveProductAccess.subjectId) {
        payload.productSubjectId = effectiveProductAccess.subjectId;
      }
      payload.productAccessStatus = effectiveProductAccess.status;
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
    const persistedSessionRole = this.isPatientPortalProductAccess(effectiveProductAccess)
      ? AccountRole.MEMBER
      : sessionRole;
    await this.prisma.refreshToken.create({
      data: {
        accountId: account.id,
        sessionRole: persistedSessionRole,
        sessionSubjectId: sessionSubjectId ?? undefined,
        activeProduct: effectiveProductAccess?.product,
        activeProductRole: effectiveProductAccess?.role,
        productSubjectId: effectiveProductAccess?.subjectId ?? undefined,
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
        role: emittedRole,
        subjectId:
          sessionRole === AccountRole.PATIENT || this.isPatientPortalProductAccess(effectiveProductAccess)
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
        activeProduct: effectiveProductAccess?.product ?? null,
        activeProductRole: effectiveProductAccess?.role ?? null,
        productSubjectId: effectiveProductAccess?.subjectId ?? null,
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

    const tokens = await this.issueTokens(stored.account, {
      scope: stored.scope,
      sessionRole: stored.sessionRole ?? undefined,
      productAccess: await this.resolveSessionProductAccess(stored.account, {
        sessionRole: stored.sessionRole ?? stored.account.role,
        activeProduct: stored.activeProduct,
        activeProductRole: stored.activeProductRole,
        productSubjectId: stored.productSubjectId,
      }),
    });
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
    const accountSnapshot = await this.prisma.account.findUnique({
      where: { id: account.id },
      include: {
        roleProfiles: true,
        productAccesses: true,
      },
    });
    if (!accountSnapshot) {
      throw new NotFoundException('Cuenta no encontrada');
    }

    const logs: DeletionOperationLog[] = [];
    const grants = this.buildAccountDeletionGrants(
      accountSnapshot,
      accountSnapshot.roleProfiles,
      accountSnapshot.productAccesses,
    );
    const doctorId = this.resolveDoctorIdForAccountDeletion(
      accountSnapshot,
      accountSnapshot.roleProfiles,
      accountSnapshot.productAccesses,
    );
    const patientId = await this.resolvePatientIdForAccountDeletion(
      accountSnapshot,
      accountSnapshot.roleProfiles,
      accountSnapshot.productAccesses,
    );
    const clinicId = this.resolveClinicIdForAccountDeletion(
      accountSnapshot,
      accountSnapshot.roleProfiles,
      accountSnapshot.productAccesses,
    );
    const employerId = this.resolveEmployerIdForAccountDeletion(
      accountSnapshot,
      accountSnapshot.roleProfiles,
      accountSnapshot.productAccesses,
    );
    await this.assertEmployerDeletionAllowed(accountSnapshot.id, employerId, meta);
    const deletedAt = new Date();
    const identitySnapshot = await this.buildIdentitySnapshot(accountSnapshot, doctorId, patientId);

    if (grants.some((grant) => grant.product === ProductCode.PATIENT_PORTAL && grant.role === ProductRole.PATIENT)) {
      logs.push(
        await this.runDeletionStep('product:patient_portal', async () => {
          if (!patientId) {
            return { skipped: 1 };
          }
          return this.deactivatePatientProductAccess(patientId);
        }),
      );
    }

    if (grants.some((grant) => grant.product === ProductCode.MEUDOC_PRO && grant.role === ProductRole.DOCTOR)) {
      logs.push(
        await this.runDeletionStep('product:meudoc_pro:doctor', async () => {
          if (!doctorId) {
            return { skipped: 1 };
          }
          return this.deactivateDoctorProductAccess(doctorId);
        }),
      );
    }

    if (grants.some((grant) => grant.product === ProductCode.MEUDOC_PRO && grant.role === ProductRole.MEDICAL_ENTITY)) {
      logs.push(
        await this.runDeletionStep('product:meudoc_pro:medical_entity', async () => {
          return this.revokeClinicAccountAccess(accountSnapshot.id, clinicId);
        }),
      );
    }

    if (
      grants.some((grant) => grant.product === ProductCode.MEUDOC_EMPLOYER)
      || grants.some((grant) => grant.product === ProductCode.PATIENT_PORTAL && grant.role === ProductRole.PATIENT)
      || Boolean(employerId)
    ) {
      logs.push(
        await this.runDeletionStep('product:meudoc_employer', async () => {
          return this.deactivateEmployerProductAccess(accountSnapshot.id, employerId);
        }),
      );
    }

    if (grants.some((grant) => grant.product === ProductCode.MEURED)) {
      logs.push(
        await this.runDeletionStep('product:meured', async () => {
          return this.deactivateMeuredProductAccess(accountSnapshot.id);
        }),
      );
    }

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
        const roleProfiles = await this.prisma.accountRoleProfile.deleteMany({
          where: { accountId: account.id },
        });
        const productAccesses = await this.prisma.accountProductAccess.deleteMany({
          where: { accountId: account.id },
        });
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
              "subjectId" = NULL,
              "doctorId" = NULL,
              "employerId" = NULL,
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
          roleProfiles: roleProfiles.count,
          productAccesses: productAccesses.count,
          accountUpdated,
        };
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
          clinicId,
          employerId,
          grants,
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

  async adminListAccounts(query: {
    page?: number;
    limit?: number;
    role?: string;
    q?: string;
    includeInsights?: boolean;
    from?: string;
    to?: string;
  }) {
    const page = Math.max(1, Number(query.page ?? 1));
    const limit = Math.min(Math.max(Number(query.limit ?? 20), 1), 100);
    const skip = (page - 1) * limit;
    const role = query.role?.toUpperCase()?.trim() || '';
    const q = query.q?.trim() || '';
    const normalizedRole = Object.values(AccountRole).includes(role as AccountRole)
      ? role as AccountRole
      : null;
    const includePatientRole = normalizedRole === AccountRole.PATIENT;
    const includeEmployerRole = normalizedRole === AccountRole.EMPLOYER;
    const filters: Prisma.AccountWhereInput[] = [{ deletedAt: null }];

    if (normalizedRole) {
      if (includePatientRole) {
        filters.push({
          OR: [
            { role: AccountRole.PATIENT },
            { roleProfiles: { some: { role: AccountRole.PATIENT } } },
          ],
        });
      } else if (includeEmployerRole) {
        filters.push({
          OR: [
            { role: AccountRole.EMPLOYER },
            { roleProfiles: { some: { role: AccountRole.EMPLOYER } } },
            {
              productAccesses: {
                some: {
                  product: ProductCode.MEUDOC_EMPLOYER,
                  role: ProductRole.EMPLOYER_ADMIN,
                  status: { not: ProductAccessStatus.DISABLED },
                },
              },
            },
          ],
        });
      } else {
        filters.push({ role: normalizedRole });
      }
    }

    if (q) {
      filters.push({
        OR: [
          { email: { contains: q, mode: 'insensitive' } },
          { phoneNumber: { contains: q } },
          { id: { equals: q } },
          { doctorId: { equals: q } },
          { employerId: { equals: q } },
          { subjectId: { equals: q } },
          ...(includePatientRole
            ? [{ roleProfiles: { some: { role: AccountRole.PATIENT, subjectId: { equals: q } } } } as Prisma.AccountWhereInput]
            : []),
          ...(includeEmployerRole
            ? [
                {
                  roleProfiles: {
                    some: { role: AccountRole.EMPLOYER, subjectId: { equals: q } },
                  },
                } as Prisma.AccountWhereInput,
                {
                  productAccesses: {
                    some: {
                      product: ProductCode.MEUDOC_EMPLOYER,
                      role: ProductRole.EMPLOYER_ADMIN,
                      subjectId: { equals: q },
                      status: { not: ProductAccessStatus.DISABLED },
                    },
                  },
                } as Prisma.AccountWhereInput,
              ]
            : []),
        ],
      });
    }

    const where: Prisma.AccountWhereInput = filters.length === 1 ? filters[0] : { AND: filters };

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
          employerId: true,
          onboardingStatus: true,
          createdAt: true,
          updatedAt: true,
          deletedAt: true,
          roleProfiles: {
            select: {
              id: true,
              role: true,
              subjectId: true,
              doctorId: true,
              onboardingStatus: true,
              createdAt: true,
              updatedAt: true,
            },
          },
          productAccesses: {
            select: {
              id: true,
              product: true,
              role: true,
              subjectId: true,
              status: true,
              createdAt: true,
              updatedAt: true,
            },
          },
        },
      }),
      this.prisma.account.count({ where }),
    ]);

    const normalizedItems = items.map((item) => {
      if (!includePatientRole) {
        if (!includeEmployerRole) {
          return item;
        }
        const employerProfile =
          item.roleProfiles.find((profile) => profile.role === AccountRole.EMPLOYER) ?? null;
        const employerProductAccess =
          item.productAccesses.find(
            (access) =>
              access.product === ProductCode.MEUDOC_EMPLOYER
              && access.role === ProductRole.EMPLOYER_ADMIN
              && access.status !== ProductAccessStatus.DISABLED,
          ) ?? null;
        return {
          ...item,
          role: AccountRole.EMPLOYER,
          subjectId:
            item.employerId
            ?? employerProductAccess?.subjectId
            ?? employerProfile?.subjectId
            ?? (item.role === AccountRole.EMPLOYER ? item.subjectId : null),
          onboardingStatus:
            employerProfile?.onboardingStatus
            ?? (item.role === AccountRole.EMPLOYER ? item.onboardingStatus : null),
        };
      }
      const patientProfile =
        item.roleProfiles.find((profile) => profile.role === AccountRole.PATIENT) ?? null;
      return {
        ...item,
        role: AccountRole.PATIENT,
        subjectId: patientProfile?.subjectId ?? (item.role === AccountRole.PATIENT ? item.subjectId : null),
        onboardingStatus:
          patientProfile?.onboardingStatus ?? (item.role === AccountRole.PATIENT ? item.onboardingStatus : null),
      };
    });

    const shouldIncludeInsights = Boolean(query.includeInsights);
    const employerInsightsRange = this.resolveEmployerInsightsRange(query.from, query.to);
    const patientInsights =
      shouldIncludeInsights && normalizedRole === AccountRole.PATIENT
        ? await this.fetchAdminPatientKpis(normalizedItems.map((item) => ({
            accountId: item.id,
            patientId: item.subjectId,
          })))
        : new Map<string, PatientAdminKpis>();
    const loginInsights =
      shouldIncludeInsights && (normalizedRole === AccountRole.PATIENT || normalizedRole === AccountRole.EMPLOYER)
        ? await this.getLoginInsights(
            normalizedItems.map((item) => item.id),
            normalizedRole === AccountRole.EMPLOYER ? AccountRole.EMPLOYER : AccountRole.PATIENT,
            normalizedRole === AccountRole.EMPLOYER ? employerInsightsRange : undefined,
          )
        : new Map<string, AccountLoginInsights>();
    const employerInsights =
      shouldIncludeInsights && normalizedRole === AccountRole.EMPLOYER
        ? await this.fetchEmployerAdminSummaries(
            normalizedItems.map((item) => ({
              accountId: item.id,
              employerId:
                ('employerId' in item && typeof item.employerId === 'string' ? item.employerId : null)
                ?? item.subjectId
                ?? null,
            })),
            employerInsightsRange,
          )
        : new Map<string, EmployerAdminSummary>();

    return {
      items: normalizedItems.map((item) => ({
        ...item,
        ...(patientInsights.has(item.id) ? patientInsights.get(item.id) : {}),
        ...(loginInsights.has(item.id) ? loginInsights.get(item.id) : {}),
        ...(employerInsights.has(item.id) ? employerInsights.get(item.id) : {}),
      })),
      page,
      limit,
      total,
    };
  }

  private getAnalyticsInternalBaseUrl() {
    return (
      this.config.get<string>('ANALYTICS_INTERNAL_BASE_URL') ??
      this.config.get<string>('ANALYTICS_BASE_URL') ??
      'http://analytics-service:3015/analyticsms'
    );
  }

  private async fetchAdminPatientKpis(patients: Array<{ accountId: string; patientId?: string | null }>) {
    const cleaned = patients
      .map((item) => ({
        accountId: item.accountId.trim(),
        patientId: item.patientId?.trim() || null,
      }))
      .filter((item) => item.accountId)
      .slice(0, 200);
    if (!cleaned.length) {
      return new Map<string, PatientAdminKpis>();
    }

    try {
      const response = await fetch(
        `${this.getAnalyticsInternalBaseUrl().replace(/\/$/, '')}/analytics/admin/reports/patients/kpis`,
        {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-role': 'SYSTEM',
          },
          body: JSON.stringify({
            accountIds: cleaned.map((item) => item.accountId),
            patients: cleaned,
          }),
        },
      );
      if (!response.ok) {
        return new Map<string, PatientAdminKpis>();
      }
      const data = (await response.json()) as { items?: PatientAdminKpis[] };
      return new Map((data.items ?? []).map((item) => [item.accountId, item]));
    } catch {
      return new Map<string, PatientAdminKpis>();
    }
  }

  private getCompanyAnalyticsInternalBaseUrl() {
    return (
      this.config.get<string>('COMPANYANALYTICS_INTERNAL_BASE_URL') ??
      'http://company-analytics-service:3053/companyanalyticsms'
    );
  }

  private getCompanyCareInternalBaseUrl() {
    return (
      this.config.get<string>('COMPANYCARE_INTERNAL_BASE_URL') ??
      'http://company-care-service:3052/companycarems'
    );
  }

  private getEmployersInternalBaseUrl() {
    return (
      this.config.get<string>('EMPLOYERS_INTERNAL_BASE_URL') ??
      this.config.get<string>('EMPLOYERS_BASE_URL') ??
      'http://employers-service:3041/employersms'
    );
  }

  private getInternalServiceHeaders() {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };
    const token = this.config.get<string>('INTERNAL_SERVICE_TOKEN') ?? '';
    if (token) {
      headers['x-internal-service-token'] = token;
    }
    return headers;
  }

  private resolveEmployerInsightsRange(from?: string, to?: string) {
    const parsedFrom = from ? new Date(from) : null;
    const parsedTo = to ? new Date(to) : null;
    if (
      parsedFrom &&
      parsedTo &&
      Number.isFinite(parsedFrom.getTime()) &&
      Number.isFinite(parsedTo.getTime()) &&
      parsedFrom.getTime() <= parsedTo.getTime()
    ) {
      return {
        from: parsedFrom,
        to: new Date(parsedTo.getTime() + 24 * 60 * 60 * 1000 - 1),
      };
    }

    const now = new Date();
    const defaultFrom = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000);
    return { from: defaultFrom, to: now };
  }

  private async fetchEmployerAdminSummaries(
    employers: Array<{ accountId: string; employerId?: string | null }>,
    range: { from: Date; to: Date },
  ) {
    const cleaned = employers
      .map((item) => ({
        accountId: item.accountId.trim(),
        employerId: item.employerId?.trim() || null,
      }))
      .filter((item) => item.accountId && item.employerId)
      .slice(0, 200) as Array<{ accountId: string; employerId: string }>;
    if (!cleaned.length) {
      return new Map<string, EmployerAdminSummary>();
    }

    const employerIds = [...new Set(cleaned.map((item) => item.employerId))];
    const [directory, careSummary, appointmentSummary] = await Promise.all([
      this.fetchEmployerDirectorySummary(employerIds),
      this.fetchEmployerCareRequestSummary(employerIds),
      this.fetchEmployerAppointmentSummary(employerIds, range),
    ]);

    return new Map(cleaned.map((item) => {
      const employerInfo = directory.get(item.employerId);
      const careInfo = careSummary.get(item.employerId);
      const appointmentInfo = appointmentSummary.get(item.employerId);
      return [
        item.accountId,
        {
          employerId: item.employerId,
          displayName: employerInfo?.displayName ?? null,
          totalCareRequests: careInfo?.totalCareRequests ?? 0,
          approvedCareRequests: careInfo?.approvedCareRequests ?? 0,
          appointmentCount: appointmentInfo?.appointmentCount ?? 0,
          hasFirstPatientAppointment: appointmentInfo?.hasFirstPatientAppointment ?? false,
        } satisfies EmployerAdminSummary,
      ];
    }));
  }

  private async fetchEmployerDirectorySummary(employerIds: string[]) {
    if (!employerIds.length) return new Map<string, { displayName: string | null }>();
    try {
      const response = await fetch(
        `${this.getEmployersInternalBaseUrl().replace(/\/$/, '')}/employers/internal/admin/summaries`,
        {
          method: 'POST',
          headers: this.getInternalServiceHeaders(),
          body: JSON.stringify({ employerIds }),
        },
      );
      if (!response.ok) {
        return new Map<string, { displayName: string | null }>();
      }
      const data = (await response.json()) as {
        items?: Array<{ employerId?: string; displayName?: string | null }>;
      };
      return new Map(
        (data.items ?? [])
          .filter((item) => typeof item.employerId === 'string' && item.employerId.trim())
          .map((item) => [
            item.employerId!.trim(),
            { displayName: item.displayName?.trim() || null },
          ]),
      );
    } catch {
      return new Map<string, { displayName: string | null }>();
    }
  }

  private async fetchEmployerCareRequestSummary(employerIds: string[]) {
    if (!employerIds.length) {
      return new Map<string, { totalCareRequests: number; approvedCareRequests: number }>();
    }
    try {
      const response = await fetch(
        `${this.getCompanyCareInternalBaseUrl().replace(/\/$/, '')}/internal/admin/employer-care-requests/summary`,
        {
          method: 'POST',
          headers: this.getInternalServiceHeaders(),
          body: JSON.stringify({ employerIds }),
        },
      );
      if (!response.ok) {
        return new Map<string, { totalCareRequests: number; approvedCareRequests: number }>();
      }
      const data = (await response.json()) as {
        items?: Array<{ employerId?: string; totalCareRequests?: number; approvedCareRequests?: number }>;
      };
      return new Map(
        (data.items ?? [])
          .filter((item) => typeof item.employerId === 'string' && item.employerId.trim())
          .map((item) => [
            item.employerId!.trim(),
            {
              totalCareRequests: Number(item.totalCareRequests ?? 0),
              approvedCareRequests: Number(item.approvedCareRequests ?? 0),
            },
          ]),
      );
    } catch {
      return new Map<string, { totalCareRequests: number; approvedCareRequests: number }>();
    }
  }

  private async fetchEmployerAppointmentSummary(employerIds: string[], range: { from: Date; to: Date }) {
    if (!employerIds.length) {
      return new Map<string, { appointmentCount: number; hasFirstPatientAppointment: boolean }>();
    }
    try {
      const response = await fetch(
        `${this.getCompanyAnalyticsInternalBaseUrl().replace(/\/$/, '')}/internal/admin/employer-appointments/summary`,
        {
          method: 'POST',
          headers: this.getInternalServiceHeaders(),
          body: JSON.stringify({
            employerIds,
            from: range.from.toISOString(),
            to: range.to.toISOString(),
          }),
        },
      );
      if (!response.ok) {
        return new Map<string, { appointmentCount: number; hasFirstPatientAppointment: boolean }>();
      }
      const data = (await response.json()) as {
        items?: Array<{ employerId?: string; appointmentCount?: number; hasFirstPatientAppointment?: boolean }>;
      };
      return new Map(
        (data.items ?? [])
          .filter((item) => typeof item.employerId === 'string' && item.employerId.trim())
          .map((item) => [
            item.employerId!.trim(),
            {
              appointmentCount: Number(item.appointmentCount ?? 0),
              hasFirstPatientAppointment: Boolean(item.hasFirstPatientAppointment),
            },
          ]),
      );
    } catch {
      return new Map<string, { appointmentCount: number; hasFirstPatientAppointment: boolean }>();
    }
  }

  private async getLoginInsights(
    accountIds: string[],
    role: AccountRole,
    range?: { from: Date; to: Date },
  ) {
    const cleaned = accountIds.filter(Boolean).slice(0, 200);
    if (!cleaned.length) {
      return new Map<string, AccountLoginInsights>();
    }

    const rows = await this.prisma.loginHistory.groupBy({
      by: ['accountId'],
      where: {
        accountId: { in: cleaned },
        role,
        ...(range
          ? {
              createdAt: {
                gte: range.from,
                lte: range.to,
              },
            }
          : {}),
      },
      _count: { _all: true },
      _max: { createdAt: true },
    });

    return new Map(rows.map((row) => [
      row.accountId,
      {
        loginCount: row._count._all,
        lastLoginAt: row._max.createdAt?.toISOString() ?? null,
      },
    ]));
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
        roleProfiles: {
          select: {
            id: true,
            role: true,
            subjectId: true,
            doctorId: true,
            onboardingStatus: true,
            createdAt: true,
            updatedAt: true,
          },
        },
        productAccesses: {
          select: {
            id: true,
            product: true,
            role: true,
            subjectId: true,
            status: true,
            createdAt: true,
            updatedAt: true,
          },
        },
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
        roleProfiles: {
          select: {
            id: true,
            role: true,
            subjectId: true,
            doctorId: true,
            onboardingStatus: true,
            createdAt: true,
            updatedAt: true,
          },
        },
        productAccesses: {
          select: {
            id: true,
            product: true,
            role: true,
            subjectId: true,
            status: true,
            createdAt: true,
            updatedAt: true,
          },
        },
      },
    });

    return updated;
  }

  async adminDeleteAccount(
    id: string,
    dto: { confirmEmail: string },
    requesterId: string | null,
    requesterRole: 'ADMIN' | 'SYSTEM',
    meta?: RequestMeta,
  ) {
    const account = await this.prisma.account.findUnique({ where: { id } });
    if (!account) {
      throw new NotFoundException('Cuenta no encontrada');
    }
    if (account.deletedAt) {
      throw new BadRequestException('Cuenta eliminada');
    }
    const normalizedConfirm = dto.confirmEmail.trim().toLowerCase();
    if (normalizedConfirm !== account.email.toLowerCase()) {
      throw new BadRequestException('El correo no coincide');
    }

    return this.executeAccountDeletion(account, AccountDeletionChannel.EMAIL, {
      ...meta,
      requesterId,
      requesterRole,
    });
  }

  async adminListEmployerCompanies(query: {
    page?: number;
    limit?: number;
    q?: string;
  }) {
    return this.employersHttp.listAdminCompanies(query);
  }

  async adminArchiveEmployerCompany(employerId: string) {
    const result = await this.employersHttp.archiveCompany(employerId);
    const affectedAccountIds = Array.from(new Set(result.affectedAuthUserIds.filter(Boolean)));
    let accountsUpdated = 0;
    let productAccessRemoved = 0;
    let roleProfilesRemoved = 0;

    for (const accountId of affectedAccountIds) {
      const [productAccesses, roleProfiles, account] = await this.prisma.$transaction([
        this.prisma.accountProductAccess.deleteMany({
          where: {
            accountId,
            product: ProductCode.MEUDOC_EMPLOYER,
          },
        }),
        this.prisma.accountRoleProfile.deleteMany({
          where: {
            accountId,
            role: AccountRole.EMPLOYER,
          },
        }),
        this.prisma.account.findUnique({
          where: { id: accountId },
          include: {
            roleProfiles: true,
            productAccesses: true,
          },
        }),
      ]);

      productAccessRemoved += productAccesses.count;
      roleProfilesRemoved += roleProfiles.count;

      if (!account) {
        continue;
      }

      const nextRole = this.resolveFallbackAccountRole(account.roleProfiles, account.productAccesses, account.role);
      const shouldUpdateLegacyEmployerLink = account.employerId === employerId || account.subjectId === employerId || account.role === AccountRole.EMPLOYER;

      await this.prisma.account.update({
        where: { id: accountId },
        data: {
          ...(shouldUpdateLegacyEmployerLink ? { employerId: null, subjectId: null } : {}),
          role: nextRole,
        },
      });
      accountsUpdated += 1;
    }

    return {
      ...result,
      authCleanup: {
        affectedAccounts: affectedAccountIds.length,
        accountsUpdated,
        productAccessRemoved,
        roleProfilesRemoved,
      },
    };
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  private async publishUserRegisteredEvent(
    account: Account,
    profile?: { firstName?: string; lastName?: string; companyName?: string; taxId?: string },
    roleOverride?: AccountRole,
    registrationContext?: AuthRegistrationSessionContext,
  ) {
    const eventRole = roleOverride ?? account.role;
    if (
      eventRole !== AccountRole.PATIENT &&
      eventRole !== AccountRole.DOCTOR &&
      eventRole !== AccountRole.CLINIC &&
      eventRole !== AccountRole.EMPLOYER
    ) {
      return;
    }

    const firstName = profile?.firstName?.trim();
    const lastName = profile?.lastName?.trim();
    const companyName = profile?.companyName?.trim();
    const taxId = profile?.taxId?.trim();
    const productAccess = registrationContext?.productAccess ?? null;
    const patientId =
      registrationContext?.patientId?.trim() ||
      productAccess?.subjectId?.trim() ||
      undefined;
    const isPatientRegistration = eventRole === AccountRole.PATIENT;

    const payload = {
      authUserId: account.id,
      role: isPatientRegistration ? AccountRole.MEMBER : eventRole,
      effectiveRole: isPatientRegistration ? 'PATIENT' : undefined,
      doctorId: account.doctorId ?? undefined,
      employerId: account.employerId ?? undefined,
      email: account.email,
      phoneNumber: account.phoneNumber ?? undefined,
      firstName: firstName || undefined,
      lastName: lastName || undefined,
      companyName: companyName || undefined,
      taxId: taxId || undefined,
      patientId,
      productSubjectId: patientId,
      activeProduct: isPatientRegistration
        ? (productAccess?.product ?? ProductCode.PATIENT_PORTAL)
        : undefined,
      activeProductRole: isPatientRegistration
        ? (productAccess?.role ?? ('PATIENT' as ProductRole))
        : undefined,
      productAccessStatus: productAccess?.status,
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

  private async findPatientIdByAuthUserId(authUserId: string): Promise<string | null> {
    return this.tryFindPatientIdByAuthUserId(authUserId);
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

  private buildAccountDeletionGrants(
    account: Account,
    roleProfiles: AccountRoleProfile[],
    productAccesses: AccountProductAccess[],
  ): AccountDeletionGrant[] {
    const grants: AccountDeletionGrant[] = productAccesses.map((access) => ({
      product: access.product,
      role: access.role,
      subjectId: access.subjectId?.trim() || null,
      source: 'product-access',
    }));

    const hasGrant = (product: ProductCode, role: ProductRole) =>
      grants.some((grant) => grant.product === product && grant.role === role);

    for (const profile of roleProfiles) {
      const mapped = this.mapRoleProfileToDeletionGrant(account, profile);
      if (!mapped || hasGrant(mapped.product, mapped.role)) {
        continue;
      }
      grants.push(mapped);
    }

    const legacyGrants = this.mapLegacyAccountToDeletionGrants(account);
    for (const grant of legacyGrants) {
      if (!hasGrant(grant.product, grant.role)) {
        grants.push(grant);
      }
    }

    return grants;
  }

  private mapRoleProfileToDeletionGrant(
    account: Account,
    profile: AccountRoleProfile,
  ): AccountDeletionGrant | null {
    switch (profile.role) {
      case AccountRole.PATIENT:
        return {
          product: ProductCode.PATIENT_PORTAL,
          role: ProductRole.PATIENT,
          subjectId: profile.subjectId?.trim() || null,
          source: 'role-profile',
        };
      case AccountRole.DOCTOR:
        return {
          product: ProductCode.MEUDOC_PRO,
          role: ProductRole.DOCTOR,
          subjectId: profile.doctorId?.trim() || profile.subjectId?.trim() || account.doctorId?.trim() || null,
          source: 'role-profile',
        };
      case AccountRole.CLINIC:
        return {
          product: ProductCode.MEUDOC_PRO,
          role: ProductRole.MEDICAL_ENTITY,
          subjectId: profile.subjectId?.trim() || null,
          source: 'role-profile',
        };
      case AccountRole.EMPLOYER:
        return {
          product: ProductCode.MEUDOC_EMPLOYER,
          role: ProductRole.EMPLOYER_ADMIN,
          subjectId: profile.subjectId?.trim() || account.employerId?.trim() || null,
          source: 'role-profile',
        };
      case AccountRole.ADMIN:
        return {
          product: ProductCode.MEUDOC_ADMIN,
          role: ProductRole.ADMIN,
          subjectId: profile.subjectId?.trim() || null,
          source: 'role-profile',
        };
      case AccountRole.COMERCIAL:
        return {
          product: ProductCode.MEUDOC_ADMIN,
          role: ProductRole.COMERCIAL,
          subjectId: profile.subjectId?.trim() || null,
          source: 'role-profile',
        };
      default:
        return null;
    }
  }

  private mapLegacyAccountToDeletionGrants(account: Account): AccountDeletionGrant[] {
    const grants: AccountDeletionGrant[] = [];
    if (account.doctorId?.trim()) {
      grants.push({
        product: ProductCode.MEUDOC_PRO,
        role: ProductRole.DOCTOR,
        subjectId: account.doctorId.trim(),
        source: 'legacy-account',
      });
    }
    if (account.employerId?.trim()) {
      grants.push({
        product: ProductCode.MEUDOC_EMPLOYER,
        role: ProductRole.EMPLOYER_ADMIN,
        subjectId: account.employerId.trim(),
        source: 'legacy-account',
      });
    }
    if (account.role === AccountRole.CLINIC && account.subjectId?.trim()) {
      grants.push({
        product: ProductCode.MEUDOC_PRO,
        role: ProductRole.MEDICAL_ENTITY,
        subjectId: account.subjectId.trim(),
        source: 'legacy-account',
      });
    }
    if (account.role === AccountRole.PATIENT) {
      grants.push({
        product: ProductCode.PATIENT_PORTAL,
        role: ProductRole.PATIENT,
        subjectId: account.subjectId?.trim() || null,
        source: 'legacy-account',
      });
    }
    return grants;
  }

  private resolveDoctorIdForAccountDeletion(
    account: Account,
    roleProfiles: AccountRoleProfile[],
    productAccesses: AccountProductAccess[],
  ): string | null {
    const roleProfile = roleProfiles.find((item) => item.role === AccountRole.DOCTOR);
    const roleDoctorId = roleProfile?.doctorId?.trim() || roleProfile?.subjectId?.trim() || null;
    if (this.isUuid(roleDoctorId)) {
      return roleDoctorId;
    }

    const productDoctorId =
      productAccesses.find(
        (item) => item.product === ProductCode.MEUDOC_PRO && item.role === ProductRole.DOCTOR,
      )?.subjectId?.trim() || null;
    if (this.isUuid(productDoctorId)) {
      return productDoctorId;
    }

    if (this.isUuid(account.doctorId)) {
      return account.doctorId!.trim();
    }

    const accountSubjectId = account.role === AccountRole.DOCTOR ? account.subjectId?.trim() || null : null;
    return this.isUuid(accountSubjectId) ? accountSubjectId : null;
  }

  private resolveClinicIdForAccountDeletion(
    account: Account,
    roleProfiles: AccountRoleProfile[],
    productAccesses: AccountProductAccess[],
  ): string | null {
    const roleClinicId =
      roleProfiles.find((item) => item.role === AccountRole.CLINIC)?.subjectId?.trim() || null;
    if (this.isUuid(roleClinicId)) {
      return roleClinicId;
    }

    const productClinicId =
      productAccesses.find(
        (item) => item.product === ProductCode.MEUDOC_PRO && item.role === ProductRole.MEDICAL_ENTITY,
      )?.subjectId?.trim() || null;
    if (this.isUuid(productClinicId)) {
      return productClinicId;
    }

    const accountSubjectId = account.role === AccountRole.CLINIC ? account.subjectId?.trim() || null : null;
    return this.isUuid(accountSubjectId) ? accountSubjectId : null;
  }

  private resolveEmployerIdForAccountDeletion(
    account: Account,
    roleProfiles: AccountRoleProfile[],
    productAccesses: AccountProductAccess[],
  ): string | null {
    const roleEmployerId =
      roleProfiles.find((item) => item.role === AccountRole.EMPLOYER)?.subjectId?.trim() || null;
    if (this.isUuid(roleEmployerId)) {
      return roleEmployerId;
    }

    const productEmployerId =
      productAccesses.find((item) => item.product === ProductCode.MEUDOC_EMPLOYER)?.subjectId?.trim() || null;
    if (this.isUuid(productEmployerId)) {
      return productEmployerId;
    }

    if (this.isUuid(account.employerId)) {
      return account.employerId!.trim();
    }

    const accountSubjectId = account.role === AccountRole.EMPLOYER ? account.subjectId?.trim() || null : null;
    return this.isUuid(accountSubjectId) ? accountSubjectId : null;
  }

  private async resolvePatientIdForAccountDeletion(
    account: Account,
    roleProfiles: AccountRoleProfile[],
    productAccesses: AccountProductAccess[],
  ): Promise<string | null> {
    const patientProfile = roleProfiles.find((item) => item.role === AccountRole.PATIENT) ?? null;
    const profileSubjectId = patientProfile?.subjectId?.trim() || null;
    if (this.isUuid(profileSubjectId)) {
      return profileSubjectId;
    }

    const patientPortalAccess =
      productAccesses.find(
        (item) => item.product === ProductCode.PATIENT_PORTAL && item.role === ProductRole.PATIENT,
      ) ?? null;
    const accessSubjectId = patientPortalAccess?.subjectId?.trim() || null;
    if (this.isUuid(accessSubjectId)) {
      return accessSubjectId;
    }

    const accountSubjectId = account.role === AccountRole.PATIENT ? account.subjectId?.trim() || null : null;
    if (this.isUuid(accountSubjectId)) {
      return accountSubjectId;
    }

    const linkedPatientId = await this.tryFindPatientIdByAuthUserId(account.id);
    if (!linkedPatientId && (account.role === AccountRole.PATIENT || patientProfile || patientPortalAccess)) {
      this.logger.warn(`No se encontro patientId vinculado para eliminar la cuenta ${account.id}`);
    }
    return linkedPatientId;
  }

  private async deactivatePatientProductAccess(patientId: string): Promise<Record<string, number>> {
    const response = await fetch(`${this.usersBaseUrl.replace(/\/$/, '')}/patients/${encodeURIComponent(patientId)}`, {
      method: 'PUT',
      headers: {
        'content-type': 'application/json',
        'x-role': 'SYSTEM',
      },
      body: JSON.stringify({ status: 'INACTIVE' }),
    });

    if (!response.ok) {
      const body = await response.text();
      throw new ServiceUnavailableException(
        `No se pudo desactivar paciente (status ${response.status}): ${body}`,
      );
    }

    return { patientInactivated: 1 };
  }

  private async deactivateDoctorProductAccess(doctorId: string): Promise<Record<string, number>> {
    const response = await fetch(
      `${this.doctorsBaseUrl.replace(/\/$/, '')}/internal/doctors/${encodeURIComponent(doctorId)}/deactivate-legacy`,
      {
        method: 'POST',
        headers: {
          'x-role': 'SYSTEM',
        },
      },
    );

    if (!response.ok) {
      const body = await response.text();
      throw new ServiceUnavailableException(
        `No se pudo desactivar doctor (status ${response.status}): ${body}`,
      );
    }

    return { doctorInactivated: 1 };
  }

  private async revokeClinicAccountAccess(
    accountId: string,
    clinicId: string | null,
  ): Promise<Record<string, number>> {
    const deleted = clinicId
      ? await this.prisma.clinicAdmin.deleteMany({
          where: {
            accountId,
            clinicId,
          },
        })
      : await this.prisma.clinicAdmin.deleteMany({ where: { accountId } });
    return { clinicAdminsRemoved: deleted.count };
  }

  private async deactivateEmployerProductAccess(
    authUserId: string,
    employerId: string | null,
  ): Promise<Record<string, number>> {
    const result = await this.employersHttp.disableAccountAccess({
      authUserId,
      employerId: employerId ?? undefined,
    });
    return {
      foundersDisabled: result.foundersDisabled,
      membersDisabled: result.membersDisabled,
      affiliatesDisabled: result.affiliatesDisabled,
      archivedEmployers: result.archivedEmployers,
    };
  }

  private async assertEmployerDeletionAllowed(
    accountId: string,
    employerId: string | null,
    meta?: RequestMeta,
  ) {
    const requesterId = meta?.requesterId?.trim() || null;
    const requesterRole = meta?.requesterRole?.trim().toUpperCase() || null;
    if (!requesterId || requesterId !== accountId) {
      return;
    }
    if (requesterRole === 'ADMIN' || requesterRole === 'SYSTEM') {
      return;
    }

    const impact = await this.employersHttp.getAccountDeletionImpact({
      authUserId: accountId,
      employerId: employerId ?? undefined,
    });
    if (impact.items.some((item) => item.wouldArchiveCompany)) {
      throw new BadRequestException(
        'No puedes eliminar tu cuenta porque eres el ultimo fundador o administrador activo de una empresa',
      );
    }
  }

  private resolveFallbackAccountRole(
    roleProfiles: AccountRoleProfile[],
    productAccesses: AccountProductAccess[],
    currentRole: AccountRole,
  ) {
    const activeProducts = productAccesses.filter((access) => access.status !== ProductAccessStatus.DISABLED);

    if (roleProfiles.some((profile) => profile.role === AccountRole.ADMIN) || currentRole === AccountRole.ADMIN) {
      return AccountRole.ADMIN;
    }
    if (roleProfiles.some((profile) => profile.role === AccountRole.COMERCIAL) || currentRole === AccountRole.COMERCIAL) {
      return AccountRole.COMERCIAL;
    }
    if (
      roleProfiles.some((profile) => profile.role === AccountRole.DOCTOR)
      || activeProducts.some((access) => access.product === ProductCode.MEUDOC_PRO && access.role === ProductRole.DOCTOR)
    ) {
      return AccountRole.DOCTOR;
    }
    if (
      roleProfiles.some((profile) => profile.role === AccountRole.CLINIC)
      || activeProducts.some((access) => access.product === ProductCode.MEUDOC_PRO && access.role === ProductRole.MEDICAL_ENTITY)
    ) {
      return AccountRole.CLINIC;
    }
    if (
      roleProfiles.some((profile) => profile.role === AccountRole.PATIENT)
      || activeProducts.some((access) => access.product === ProductCode.PATIENT_PORTAL && access.role === ProductRole.PATIENT)
    ) {
      return AccountRole.PATIENT;
    }
    if (activeProducts.some((access) => access.product === ProductCode.MEURED)) {
      return AccountRole.MEMBER;
    }
    return currentRole === AccountRole.EMPLOYER ? AccountRole.MEMBER : currentRole;
  }

  private async deactivateMeuredProductAccess(authUserId: string): Promise<Record<string, number>> {
    const result = await this.registrationPrefill.disableMeuredProfile(authUserId);
    return {
      membershipsDeleted: result.membershipsDeleted,
      settingsDeleted: result.settingsDeleted,
      verificationsDeleted: result.verificationsDeleted,
      statsDeleted: result.statsDeleted,
      profilesDeleted: result.profilesDeleted,
    };
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
    const existingByAuth = await this.tryFindPatientIdByAuthUserId(account.id);
    if (existingByAuth) {
      return existingByAuth;
    }

    const existing = await this.findPatientByContact(account.email, account.phoneNumber ?? undefined);
    if (existing?.patientId) {
      const existingAuthUserId = existing.authUserId?.trim() || null;
      if (existingAuthUserId && existingAuthUserId !== account.id) {
        const linkedAccount = await this.prisma.account.findUnique({
          where: { id: existingAuthUserId },
        });
        if (linkedAccount) {
          const canReclaimPatient =
            existing.matchedByEmail ||
            linkedAccount.email.trim().toLowerCase() === account.email.trim().toLowerCase();
          if (!canReclaimPatient) {
            throw new ConflictException('El paciente ya tiene una cuenta vinculada');
          }
        }
      }
      await this.linkAuthUserToPatient({
        patientId: existing.patientId,
        authUserId: account.id,
        expectedAuthUserId:
          existingAuthUserId && existingAuthUserId !== account.id ? existingAuthUserId : undefined,
        email: account.email,
        phoneNumber: account.phoneNumber ?? undefined,
      });
      return existing.patientId;
    }
    return this.createPatientForAccount(account, firstName, lastName);
  }

  private async findPatientByContact(
    email: string,
    phoneNumber?: string,
  ): Promise<{ patientId: string; authUserId: string | null; matchedByEmail: boolean } | null> {
    const base = this.usersBaseUrl.replace(/\/$/, '');
    const headers = { 'x-role': 'SYSTEM' };
    if (phoneNumber) {
      try {
        const response = await fetch(`${base}/patients/search?phone=${encodeURIComponent(phoneNumber)}`, { headers });
        if (response.ok) {
          const data = (await response.json()) as {
            items?: Array<{
              id: string;
              authUserId?: string | null;
              status?: string | null;
              contacts?: Array<{ email?: string | null }>;
            }>;
          };
          const lowerEmail = email.toLowerCase();
          const activeItems = (data.items ?? []).filter((item) => this.isReusablePatientCandidate(item.status));
          const emailMatch = activeItems.find((item) =>
            item.contacts?.some((contact) => (contact.email ?? '').toLowerCase() === lowerEmail),
          );
          const match = emailMatch ?? activeItems[0];
          if (match?.id) {
            if (emailMatch) {
              return {
                patientId: match.id,
                authUserId: match.authUserId ?? null,
                matchedByEmail: true,
              };
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
      const data = (await response.json()) as {
        items?: Array<{
          id: string;
          authUserId?: string | null;
          status?: string | null;
          contacts?: Array<{ email?: string | null }>;
        }>;
      };
      const lower = email.toLowerCase();
      const activeItems = (data.items ?? []).filter((item) => this.isReusablePatientCandidate(item.status));
      const emailMatch = activeItems.find((item) =>
        item.contacts?.some((contact) => (contact.email ?? '').toLowerCase() === lower),
      );
      const match = emailMatch ?? activeItems[0];
      if (!match?.id) return null;
      return {
        patientId: match.id,
        authUserId: match.authUserId ?? null,
        matchedByEmail: Boolean(emailMatch),
      };
    } catch {
      return null;
    }
  }

  private isReusablePatientCandidate(status?: string | null) {
    return (status ?? 'ACTIVE').toUpperCase() === 'ACTIVE';
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
    if (await this.accountHasRole(account, AccountRole.PATIENT)) {
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

  private parseAccountRole(role?: string | null): AccountRole | null {
    if (!role) {
      return null;
    }
    return Object.values(AccountRole).includes(role as AccountRole)
      ? (role as AccountRole)
      : null;
  }

  private parseProductCode(product?: string | null): ProductCode | null {
    if (!product) {
      return null;
    }
    return Object.values(ProductCode).includes(product as ProductCode)
      ? (product as ProductCode)
      : null;
  }

  private parseProductRole(role?: string | null): ProductRole | null {
    if (!role) {
      return null;
    }
    return Object.values(ProductRole).includes(role as ProductRole)
      ? (role as ProductRole)
      : null;
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
      productAccess?: ProductAccessContext | null;
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
    const productAccess = options?.productAccess ?? null;
    const challenge = await this.prisma.twoFactorChallenge.create({
      data: {
        id,
        accountId: account.id,
        sessionRole: options?.sessionRole,
        activeProduct: productAccess?.product,
        activeProductRole: productAccess?.role,
        productSubjectId: productAccess?.subjectId ?? undefined,
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
      productAccess?: ProductAccessContext | null;
      availableRoles?: AccountRole[];
      availableProductAccess?: Awaited<ReturnType<AuthService['getAvailableProductAccess']>>;
    } = {},
  ) {
    const sessionRole = options.sessionRole ?? account.role;
    const productAccess = await this.resolveSessionProductAccess(account, {
      sessionRole,
      productAccess: options.productAccess,
    });
    const method = this.resolveTwoFactorMethod(account);
    const challenge = await this.createTwoFactorChallenge(account, {
      sessionRole,
      productAccess,
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

  private getLoginProductIntent(requestedRole: AccountRole): LoginProductIntent | null {
    if (requestedRole === AccountRole.DOCTOR) {
      return {
        accountRole: AccountRole.DOCTOR,
        product: ProductCode.MEUDOC_PRO,
        productRoles: [ProductRole.DOCTOR],
      };
    }
    if (requestedRole === AccountRole.PATIENT) {
      return {
        accountRole: AccountRole.PATIENT,
        product: ProductCode.PATIENT_PORTAL,
        productRoles: [ProductRole.PATIENT],
      };
    }
    if (requestedRole === AccountRole.EMPLOYER) {
      return {
        accountRole: AccountRole.EMPLOYER,
        product: ProductCode.MEUDOC_EMPLOYER,
        productRoles: [ProductRole.EMPLOYER_ADMIN, ProductRole.EMPLOYER_BILLING],
      };
    }
    return null;
  }

  private async resolveProductLoginContext(account: Account, requestedRole: AccountRole) {
    const intent = this.getLoginProductIntent(requestedRole);
    if (!intent) {
      return null;
    }

    const [roleProfile, productAccesses, availableProductAccess] = await Promise.all([
      this.getRoleProfile(account.id, intent.accountRole),
      this.prisma.accountProductAccess.findMany({
        where: {
          accountId: account.id,
          product: intent.product,
          role: { in: intent.productRoles },
        },
        orderBy: { createdAt: 'asc' },
      }),
      this.getAvailableProductAccess(account.id),
    ]);

    const activeProductAccess = productAccesses.find(
      (access) => access.status === ProductAccessStatus.ACTIVE,
    );
    if (!roleProfile || !activeProductAccess) {
      if (productAccesses.length > 0 && !activeProductAccess) {
        throw new UnauthorizedException('Acceso de producto no activo');
      }
      const registrationPrefill = await this.registrationPrefill.build(account);
      throw new BadRequestException({
        code: 'PRODUCT_ACCESS_REQUIRED',
        message: 'Esta cuenta no tiene activo el acceso solicitado',
        requestedRole,
        requestedProduct: intent.product,
        requestedProductRoles: intent.productRoles,
        availableProductAccess,
        registrationPrefill,
      });
    }

    this.assertProductLoginSubject(account, intent, roleProfile, activeProductAccess);
    return {
      sessionRole: requestedRole,
      productAccess: this.toProductAccessContext(activeProductAccess),
    };
  }

  private assertProductLoginSubject(
    account: Account,
    intent: LoginProductIntent,
    roleProfile: {
      subjectId: string | null;
      doctorId: string | null;
    },
    productAccess: {
      subjectId: string | null;
    },
  ) {
    const profileSubjectId =
      intent.accountRole === AccountRole.DOCTOR
        ? roleProfile.doctorId?.trim() || roleProfile.subjectId?.trim() || account.doctorId?.trim()
        : roleProfile.subjectId?.trim();
    const productSubjectId = productAccess.subjectId?.trim();
    if (!profileSubjectId || !productSubjectId || profileSubjectId !== productSubjectId) {
      throw new UnauthorizedException('La vinculacion del acceso de producto es inconsistente');
    }
  }

  private async assertProductAccessProfile(
    account: Account,
    productAccess: {
      product: ProductCode;
      role: ProductRole;
      subjectId: string | null;
    },
  ) {
    const requiredRole =
      productAccess.product === ProductCode.PATIENT_PORTAL && productAccess.role === ProductRole.PATIENT
        ? AccountRole.PATIENT
        : productAccess.product === ProductCode.MEUDOC_PRO && productAccess.role === ProductRole.DOCTOR
          ? AccountRole.DOCTOR
          : productAccess.product === ProductCode.MEUDOC_EMPLOYER &&
              (productAccess.role === ProductRole.EMPLOYER_ADMIN ||
                productAccess.role === ProductRole.EMPLOYER_BILLING)
            ? AccountRole.EMPLOYER
            : null;
    if (!requiredRole) {
      return;
    }
    const roleProfile = await this.getRoleProfile(account.id, requiredRole);
    if (!roleProfile) {
      throw new UnauthorizedException('Perfil de producto no disponible');
    }
    const intent = this.getLoginProductIntent(requiredRole);
    if (!intent) {
      throw new UnauthorizedException('Perfil de producto no disponible');
    }
    this.assertProductLoginSubject(account, intent, roleProfile, productAccess);
  }

  private async getAvailableRoles(account: Account): Promise<AccountRole[]> {
    const profiles = await this.prisma.accountRoleProfile.findMany({
      where: { accountId: account.id },
      select: { role: true },
    });
    const roles = new Set<AccountRole>([account.role, ...profiles.map((p) => p.role)]);
    if (roles.has(AccountRole.MEMBER) && roles.size > 1) {
      roles.delete(AccountRole.MEMBER);
    }
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

  private async getRoleProfile(accountId: string, role: AccountRole) {
    return this.prisma.accountRoleProfile.findUnique({
      where: { accountId_role: { accountId, role } },
    });
  }

  private async accountHasRole(account: Account, role: AccountRole) {
    if (account.role === role) {
      return true;
    }
    return Boolean(await this.getRoleProfile(account.id, role));
  }

  private async provisionPatientAccessForAccount(
    account: Account,
    options: { patientId?: string | null; firstName?: string; lastName?: string } = {},
  ) {
    let patientId = options.patientId?.trim() || null;
    if (!patientId) {
      const profile = await this.getRoleProfile(account.id, AccountRole.PATIENT);
      const profileSubjectId = profile?.subjectId?.trim() || null;
      patientId = profileSubjectId && this.isUuid(profileSubjectId) ? profileSubjectId : null;
    }
    if (!patientId) {
      patientId = await this.tryFindPatientIdByAuthUserId(account.id);
    }
    if (!patientId) {
      const firstName = options.firstName?.trim();
      const lastName = options.lastName?.trim();
      patientId =
        firstName && lastName
          ? await this.linkOrCreatePatientForAccount(account, firstName, lastName)
          : await this.resolvePatientIdForSession(account);
    }

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

    const productAccess = await this.ensureProductAccess(
      account.id,
      ProductCode.PATIENT_PORTAL,
      'PATIENT' as ProductRole,
      patientId,
    );

    return { patientId, productAccess };
  }

  private toProductAccessContext(
    access: {
      id: string;
      product: ProductCode;
      role: ProductRole;
      subjectId: string | null;
      status: ProductAccessStatus;
    },
    subjectIdHint?: string | null,
  ): ProductAccessContext {
    return {
      id: access.id,
      product: access.product,
      role: access.role,
      subjectId: subjectIdHint?.trim() || access.subjectId,
      status: access.status,
    };
  }

  private assertActiveProductAccessStatus(
    status: ProductAccessStatus,
    options?: { allowPending?: boolean },
  ) {
    if (status === ProductAccessStatus.DISABLED || status === ProductAccessStatus.SUSPENDED) {
      throw new UnauthorizedException('Acceso de producto inactivo');
    }
    if (status === ProductAccessStatus.PENDING && !options?.allowPending) {
      throw new UnauthorizedException('Acceso de producto pendiente');
    }
  }

  private async loadAccountProductAccess(
    accountId: string,
    product: ProductCode,
    role: ProductRole,
    options?: { subjectIdHint?: string | null; allowPending?: boolean },
  ): Promise<ProductAccessContext> {
    const access = await this.prisma.accountProductAccess.findFirst({
      where: {
        accountId,
        product,
        role,
      },
    });
    if (!access) {
      throw new UnauthorizedException('Acceso de producto no disponible');
    }
    this.assertActiveProductAccessStatus(access.status, options);
    return this.toProductAccessContext(access, options?.subjectIdHint);
  }

  private async resolveSessionProductAccess(
    account: Account,
    input: SessionProductAccessInput,
  ): Promise<ProductAccessContext | null> {
    if (input.productAccess) {
      if (input.productAccess.id) {
        const access = await this.prisma.accountProductAccess.findUnique({
          where: { id: input.productAccess.id },
        });
        if (!access || access.accountId !== account.id) {
          throw new UnauthorizedException('Acceso de producto no disponible');
        }
        this.assertActiveProductAccessStatus(access.status);
        return this.toProductAccessContext(
          access,
          input.productAccess.subjectId ?? input.productSubjectId,
        );
      }
      return this.loadAccountProductAccess(
        account.id,
        input.productAccess.product,
        input.productAccess.role,
        { subjectIdHint: input.productAccess.subjectId ?? input.productSubjectId },
      );
    }

    if (input.activeProduct && input.activeProductRole) {
      return this.loadAccountProductAccess(
        account.id,
        input.activeProduct,
        input.activeProductRole,
        { subjectIdHint: input.productSubjectId },
      );
    }

    const sessionRole = input.sessionRole ?? account.role;
    if (sessionRole === AccountRole.PATIENT) {
      const patientSession = await this.resolvePatientPortalSession(account);
      return patientSession.productAccess;
    }

    return null;
  }

  private isPatientPortalProductAccess(productAccess?: ProductAccessContext | null) {
    return Boolean(
      productAccess &&
      productAccess.product === ProductCode.PATIENT_PORTAL &&
      productAccess.role === ('PATIENT' as ProductRole),
    );
  }

  private async resolvePatientPortalSession(
    account: Account,
    productAccess?: ProductAccessContext | null,
  ): Promise<ResolvedPatientPortalSession> {
    let resolvedProductAccess = this.isPatientPortalProductAccess(productAccess)
      ? productAccess!
      : await this.prisma.accountProductAccess.findFirst({
          where: {
            accountId: account.id,
            product: ProductCode.PATIENT_PORTAL,
            role: 'PATIENT' as ProductRole,
          },
        });

    if (!resolvedProductAccess) {
      const hasPatientRole = await this.accountHasRole(account, AccountRole.PATIENT);
      if (!hasPatientRole) {
        throw new UnauthorizedException('Acceso al portal paciente no disponible');
      }
      const provisionedPatientAccess = await this.provisionPatientAccessForAccount(account);
      resolvedProductAccess = provisionedPatientAccess.productAccess;
    }

    if (resolvedProductAccess.status !== ProductAccessStatus.ACTIVE) {
      throw new UnauthorizedException('Acceso al portal paciente no activo');
    }

    const patientId =
      resolvedProductAccess.subjectId?.trim() ||
      (await this.resolvePatientIdForSession(account, productAccess?.subjectId ?? null));

    return {
      patientId,
      productAccess: {
        ...resolvedProductAccess,
        subjectId: patientId,
      },
    };
  }

  private resolveSessionRoleForProductAccess(account: Account, productAccess: ProductAccessContext): AccountRole {
    if (productAccess.product === ProductCode.PATIENT_PORTAL && productAccess.role === ('PATIENT' as ProductRole)) {
      return AccountRole.MEMBER;
    }
    if (productAccess.product === ProductCode.MEUDOC_PRO) {
      if (productAccess.role === ProductRole.DOCTOR) return AccountRole.DOCTOR;
      if (productAccess.role === ProductRole.MEDICAL_ENTITY) return AccountRole.CLINIC;
    }
    if (productAccess.product === ProductCode.MEUDOC_EMPLOYER) {
      if (
        productAccess.role === ProductRole.EMPLOYER_ADMIN ||
        productAccess.role === ProductRole.EMPLOYER_BILLING
      ) {
        return AccountRole.EMPLOYER;
      }
    }
    if (productAccess.product === ProductCode.MEUDOC_ADMIN) {
      if (productAccess.role === ProductRole.ADMIN) return AccountRole.ADMIN;
      if (productAccess.role === ProductRole.COMERCIAL) return AccountRole.COMERCIAL;
    }
    return account.role;
  }

  private async ensureLegacyProductAccess(account: Account) {
    if (account.role === AccountRole.DOCTOR && account.doctorId) {
      await this.prisma.accountRoleProfile.upsert({
        where: { accountId_role: { accountId: account.id, role: AccountRole.DOCTOR } },
        create: {
          accountId: account.id,
          role: AccountRole.DOCTOR,
          subjectId: account.doctorId,
          doctorId: account.doctorId,
          onboardingStatus: account.onboardingStatus,
        },
        update: {
          subjectId: account.doctorId,
          doctorId: account.doctorId,
        },
      });
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_PRO, ProductRole.DOCTOR, account.doctorId);
    }
    if (account.role === AccountRole.CLINIC && account.subjectId) {
      await this.ensureProductAccess(account.id, ProductCode.MEUDOC_PRO, ProductRole.MEDICAL_ENTITY, account.subjectId);
    }
    if (account.role === AccountRole.EMPLOYER && account.employerId) {
      await this.prisma.accountRoleProfile.upsert({
        where: { accountId_role: { accountId: account.id, role: AccountRole.EMPLOYER } },
        create: {
          accountId: account.id,
          role: AccountRole.EMPLOYER,
          subjectId: account.employerId,
          onboardingStatus: account.onboardingStatus,
        },
        update: {
          subjectId: account.employerId,
        },
      });
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
    if (sessionSubjectId && this.isUuid(sessionSubjectId)) {
      return sessionSubjectId;
    }
    const patientProfile = await this.getRoleProfile(account.id, AccountRole.PATIENT);
    if (patientProfile?.subjectId && this.isUuid(patientProfile.subjectId)) {
      return patientProfile.subjectId;
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

  private isUuid(value?: string | null) {
    if (!value) return false;
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value.trim(),
    );
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
