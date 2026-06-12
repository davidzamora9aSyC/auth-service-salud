import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  AccountRole,
  DoctorReferralStatus,
  Prisma,
} from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CreateDoctorReferralDto } from './dto/create-doctor-referral.dto';
import { ListDoctorReferralsDto } from './dto/list-doctor-referrals.dto';
import { UpdateDoctorReferralDto } from './dto/update-doctor-referral.dto';

const STATUSES_BEFORE_ACCOUNT_CREATED: DoctorReferralStatus[] = [
  DoctorReferralStatus.NEW,
  DoctorReferralStatus.IN_CONTACT,
  DoctorReferralStatus.INTERESTED,
  DoctorReferralStatus.ONBOARDING_SENT,
];

const STATUSES_BEFORE_ACTIVE: DoctorReferralStatus[] = [
  ...STATUSES_BEFORE_ACCOUNT_CREATED,
  DoctorReferralStatus.ACCOUNT_CREATED,
];

type ReferralActor = {
  role: 'ADMIN' | 'COMERCIAL' | 'SYSTEM';
  authUserId: string;
};

@Injectable()
export class DoctorReferralsService {
  private readonly analyticsBaseUrl: string;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {
    this.analyticsBaseUrl =
      this.config.get<string>('ANALYTICS_INTERNAL_BASE_URL') ??
      'http://analytics-service:3015/analyticsms';
  }

  async createReferral(actor: ReferralActor, dto: CreateDoctorReferralDto) {
    if (actor.role !== 'COMERCIAL') {
      throw new ForbiddenException('No autorizado');
    }

    await this.assertCommercialAccount(actor.authUserId);

    const fullName = dto.fullName.trim();
    const phoneNumber = this.normalizePhoneNumber(dto.phoneNumber);
    const email = dto.email?.trim().toLowerCase() || null;
    const status = dto.status ?? DoctorReferralStatus.NEW;
    const statusNote = dto.statusNote?.trim() || null;

    await this.assertNoDuplicateReferral(phoneNumber, email);

    const referral = await this.prisma.doctorReferral.create({
      data: {
        salesRepId: actor.authUserId,
        fullName,
        phoneNumber,
        email,
        status,
        statusNote,
      },
      include: this.referralInclude(),
    });

    return this.toReferralResponse(referral);
  }

  async listReferralsForCommercial(authUserId: string, query: ListDoctorReferralsDto) {
    await this.assertCommercialAccount(authUserId);
    return this.listReferrals(query, { salesRepId: authUserId });
  }

  async listReferralsForAdmin(query: ListDoctorReferralsDto) {
    const salesRepId = query.salesRepId?.trim() || undefined;
    return this.listReferrals(query, salesRepId ? { salesRepId } : {});
  }

  async getReferralForCommercial(authUserId: string, referralId: string) {
    await this.assertCommercialAccount(authUserId);
    const referral = await this.findReferralOrThrow(referralId);
    if (referral.salesRepId !== authUserId) {
      throw new ForbiddenException('No autorizado');
    }
    return this.toReferralResponse(referral);
  }

  async getReferralForAdmin(referralId: string) {
    const referral = await this.findReferralOrThrow(referralId);
    return this.toReferralResponse(referral);
  }

  async updateReferralForCommercial(
    authUserId: string,
    referralId: string,
    dto: UpdateDoctorReferralDto,
  ) {
    await this.assertCommercialAccount(authUserId);
    const referral = await this.findReferralOrThrow(referralId);
    if (referral.salesRepId !== authUserId) {
      throw new ForbiddenException('No autorizado');
    }
    if (dto.salesRepId) {
      throw new BadRequestException('No puedes reasignar el vendedor');
    }
    return this.applyReferralUpdate(referral.id, dto);
  }

  async updateReferralForAdmin(referralId: string, dto: UpdateDoctorReferralDto) {
    await this.findReferralOrThrow(referralId);
    return this.applyReferralUpdate(referralId, dto);
  }

  async getReferralMetricsForAdmin(referralId: string) {
    const referral = await this.findReferralOrThrow(referralId);
    if (!referral.doctorId) {
      return {
        referralId: referral.id,
        doctorId: null,
        loginCount: 0,
        appointmentCount: 0,
        doctorOnboardingStatus: null,
      };
    }

    const doctorAccount = await this.prisma.account.findFirst({
      where: {
        doctorId: referral.doctorId,
        role: AccountRole.DOCTOR,
        deletedAt: null,
      },
      select: {
        id: true,
        onboardingStatus: true,
      },
    });

    const loginCount = doctorAccount
      ? await this.prisma.loginHistory.count({
          where: {
            accountId: doctorAccount.id,
            role: AccountRole.DOCTOR,
          },
        })
      : 0;

    const appointmentCount = await this.fetchAppointmentCount(referral.doctorId);

    return {
      referralId: referral.id,
      doctorId: referral.doctorId,
      loginCount,
      appointmentCount,
      doctorOnboardingStatus: doctorAccount?.onboardingStatus ?? null,
    };
  }

  async linkReferralToOnboardingInvite(input: {
    referralId: string;
    salesRepId: string;
    doctorId: string;
    onboardingInviteId: string;
  }) {
    const referral = await this.prisma.doctorReferral.findUnique({
      where: { id: input.referralId },
    });
    if (!referral || referral.salesRepId !== input.salesRepId) {
      throw new NotFoundException('Referido no encontrado');
    }

    const updated = await this.prisma.doctorReferral.update({
      where: { id: referral.id },
      data: {
        doctorId: input.doctorId,
        onboardingInviteId: input.onboardingInviteId,
      },
      include: this.referralInclude(),
    });

    return this.toReferralResponse(updated);
  }

  async onDoctorAccountRegistered(doctorId: string) {
    await this.promoteReferralStatus(
      doctorId,
      DoctorReferralStatus.ACCOUNT_CREATED,
      STATUSES_BEFORE_ACCOUNT_CREATED,
    );
  }

  async onDoctorOnboardingCompleted(doctorId: string) {
    await this.promoteReferralStatus(
      doctorId,
      DoctorReferralStatus.ACTIVE,
      STATUSES_BEFORE_ACTIVE,
    );
  }

  private async listReferrals(
    query: ListDoctorReferralsDto,
    scope: { salesRepId?: string },
  ) {
    const page = Math.max(1, Number(query.page ?? 1));
    const limit = Math.min(Math.max(Number(query.limit ?? 20), 1), 100);
    const skip = (page - 1) * limit;
    const q = query.q?.trim() || '';

    const where: Prisma.DoctorReferralWhereInput = {};
    if (scope.salesRepId) {
      where.salesRepId = scope.salesRepId;
    }
    if (query.status) {
      where.status = query.status;
    }
    if (q) {
      where.OR = [
        { fullName: { contains: q, mode: 'insensitive' } },
        { phoneNumber: { contains: q } },
        { email: { contains: q, mode: 'insensitive' } },
        { id: { equals: q } },
        { doctorId: { equals: q } },
      ];
    }

    const [items, total] = await this.prisma.$transaction([
      this.prisma.doctorReferral.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: this.referralInclude(),
      }),
      this.prisma.doctorReferral.count({ where }),
    ]);

    return {
      items: items.map((item) => this.toReferralResponse(item)),
      page,
      limit,
      total,
    };
  }

  private async applyReferralUpdate(referralId: string, dto: UpdateDoctorReferralDto) {
    const existing = await this.findReferralOrThrow(referralId);

    const nextPhone = dto.phoneNumber ? this.normalizePhoneNumber(dto.phoneNumber) : undefined;
    const nextEmail =
      dto.email === null ? null : dto.email !== undefined ? dto.email.trim().toLowerCase() : undefined;

    if (nextPhone && nextPhone !== existing.phoneNumber) {
      await this.assertNoDuplicateReferral(nextPhone, nextEmail ?? existing.email, referralId);
    } else if (nextEmail && nextEmail !== existing.email) {
      await this.assertNoDuplicateReferral(existing.phoneNumber, nextEmail, referralId);
    }

    if (dto.salesRepId && dto.salesRepId !== existing.salesRepId) {
      const salesRep = await this.prisma.account.findFirst({
        where: {
          id: dto.salesRepId,
          role: AccountRole.COMERCIAL,
          deletedAt: null,
        },
        select: { id: true },
      });
      if (!salesRep) {
        throw new BadRequestException('Vendedor comercial no valido');
      }
    }

    const updated = await this.prisma.doctorReferral.update({
      where: { id: referralId },
      data: {
        fullName: dto.fullName?.trim() || undefined,
        phoneNumber: nextPhone,
        email: nextEmail,
        status: dto.status,
        statusNote: dto.statusNote === null ? null : dto.statusNote?.trim() || undefined,
        salesRepId: dto.salesRepId,
      },
      include: this.referralInclude(),
    });

    return this.toReferralResponse(updated);
  }

  private async promoteReferralStatus(
    doctorId: string,
    targetStatus: DoctorReferralStatus,
    allowedCurrentStatuses: DoctorReferralStatus[],
  ) {
    const referral = await this.prisma.doctorReferral.findUnique({
      where: { doctorId },
    });
    if (!referral || !allowedCurrentStatuses.includes(referral.status)) {
      return;
    }

    await this.prisma.doctorReferral.update({
      where: { id: referral.id },
      data: { status: targetStatus },
    });
  }

  private async assertCommercialAccount(authUserId: string) {
    const account = await this.prisma.account.findFirst({
      where: {
        id: authUserId,
        role: AccountRole.COMERCIAL,
        deletedAt: null,
        status: 'ACTIVE',
      },
      select: { id: true },
    });
    if (!account) {
      throw new ForbiddenException('Cuenta comercial no valida');
    }
  }

  private async assertNoDuplicateReferral(
    phoneNumber: string,
    email: string | null | undefined,
    excludeReferralId?: string,
  ) {
    const existingByPhone = await this.prisma.doctorReferral.findFirst({
      where: {
        phoneNumber,
        ...(excludeReferralId ? { id: { not: excludeReferralId } } : {}),
      },
      select: { id: true },
    });
    if (existingByPhone) {
      throw new ConflictException('Ya existe un referido con ese telefono');
    }

    if (email) {
      const existingByEmail = await this.prisma.doctorReferral.findFirst({
        where: {
          email,
          ...(excludeReferralId ? { id: { not: excludeReferralId } } : {}),
        },
        select: { id: true },
      });
      if (existingByEmail) {
        throw new ConflictException('Ya existe un referido con ese correo');
      }
    }
  }

  private async findReferralOrThrow(referralId: string) {
    const referral = await this.prisma.doctorReferral.findUnique({
      where: { id: referralId },
      include: this.referralInclude(),
    });
    if (!referral) {
      throw new NotFoundException('Referido no encontrado');
    }
    return referral;
  }

  private referralInclude() {
    return {
      salesRep: {
        select: {
          id: true,
          email: true,
        },
      },
    } satisfies Prisma.DoctorReferralInclude;
  }

  private toReferralResponse(
    referral: Prisma.DoctorReferralGetPayload<{ include: ReturnType<DoctorReferralsService['referralInclude']> }>,
  ) {
    return {
      id: referral.id,
      salesRepId: referral.salesRepId,
      salesRepEmail: referral.salesRep.email,
      fullName: referral.fullName,
      phoneNumber: referral.phoneNumber,
      email: referral.email,
      status: referral.status,
      statusNote: referral.statusNote,
      doctorId: referral.doctorId,
      onboardingInviteId: referral.onboardingInviteId,
      createdAt: referral.createdAt.toISOString(),
      updatedAt: referral.updatedAt.toISOString(),
    };
  }

  private normalizePhoneNumber(value: string) {
    const trimmed = value.replace(/[\s.-]/g, '');
    if (!trimmed.startsWith('+')) {
      return `+${trimmed}`;
    }
    return trimmed;
  }

  private async fetchAppointmentCount(doctorId: string) {
    const from = new Date('2020-01-01T00:00:00.000Z').toISOString();
    const to = new Date(Date.now() + 86400000).toISOString();
    const url = `${this.analyticsBaseUrl.replace(/\/$/, '')}/analytics/admin/reports/appointments/booked-count-by-doctor`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-role': 'SYSTEM',
        },
        body: JSON.stringify({
          doctorIds: [doctorId],
          from,
          to,
        }),
      });
      if (!response.ok) {
        return 0;
      }
      const data = (await response.json()) as {
        items?: Array<{ doctorId: string; bookedAppointments: number }>;
      };
      return data.items?.find((item) => item.doctorId === doctorId)?.bookedAppointments ?? 0;
    } catch {
      return 0;
    }
  }
}
