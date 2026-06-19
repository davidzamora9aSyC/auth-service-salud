import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { randomBytes, randomUUID, createHash } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { InviteStatus, TrialDurationUnit } from '@prisma/client';
import { CreateDoctorOnboardingInviteDto } from './dto/create-doctor-onboarding-invite.dto';
import { CreatePublicDoctorDto } from './dto/create-public-doctor.dto';
import { RabbitmqService } from './rabbitmq.service';
import { AdminListDoctorOnboardingInvitesDto } from './dto/admin-list-doctor-onboarding-invites.dto';
import type { DoctorOnboardingInviteAdminListResponse, DoctorOnboardingInviteOnboardingInfo } from './types/doctor-onboarding-invite-admin.types';
import { DoctorReferralsService } from './doctor-referrals.service';
import { UpdateDoctorOnboardingSettingsDto } from './dto/update-doctor-onboarding-settings.dto';

type OnboardingActor = {
  role?: string;
  authUserId?: string;
};

type PrefillProfile = {
  firstName?: string;
  lastName?: string;
  secondLastName?: string;
  gender?: string;
  documentNumber?: string;
  birthCity?: string;
  birthProvince?: string;
  nationality?: string;
  bio?: string;
  specialties?: string[];
};

type PrefillAddress = {
  label?: string;
  type?: string;
  city?: string;
  address?: string;
  postalCode?: string;
  additionalInfo?: string;
  website?: string;
  insurancePreference?: string;
  timezone?: string;
};

type PrefillAgendaRule = {
  dayOfWeek: number;
  startTime: string;
  endTime: string;
  slotMinutes?: number;
};

type PrefillAgenda = {
  workingHours?: PrefillAgendaRule[];
};

type PrefillService = {
  name: string;
  durationMinutes: number;
  priceAmount?: number;
  currency?: string;
  showInMeuSalud?: boolean;
  reserveOnline?: boolean;
};

@Injectable()
export class AdminOnboardingService {
  private readonly doctorsBaseUrl: string;
  private readonly doctorsInternalBaseUrl: string;
  private readonly availabilityBaseUrl: string;
  private readonly servicesBaseUrl: string;
  private readonly inviteTtlMs: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly rabbitmq: RabbitmqService,
    private readonly referrals: DoctorReferralsService,
  ) {
    this.doctorsBaseUrl =
      this.config.get<string>('DOCTORS_BASE_URL') ??
      'http://doctors-service:3009/doctorsms';
    this.doctorsInternalBaseUrl =
      this.config.get<string>('DOCTORS_INTERNAL_BASE_URL') ?? this.doctorsBaseUrl;
    this.availabilityBaseUrl =
      this.config.get<string>('AVAILABILITY_BASE_URL') ??
      'http://availability-service:3012/availabilityms';
    this.servicesBaseUrl =
      this.config.get<string>('SERVICES_BASE_URL') ??
      'http://services-service:3011/servicesms';
    this.inviteTtlMs = parseInt(
      this.config.get<string>('DOCTOR_ONBOARDING_INVITE_TTL_MS', '1209600000'),
      10,
    ); // 14 dias por defecto
  }

  async listInvites(
    query: AdminListDoctorOnboardingInvitesDto,
    actor?: OnboardingActor,
  ): Promise<DoctorOnboardingInviteAdminListResponse> {
    const page = query.page && query.page > 0 ? query.page : 1;
    const limit = query.limit && query.limit > 0 ? Math.min(query.limit, 100) : 50;
    const skip = (page - 1) * limit;
    const q = (query.q ?? '').trim().toLowerCase();

    const where: {
      OR?: Array<Record<string, unknown>>;
      createdByUserId?: string;
    } = {};

    if (actor?.role === 'COMERCIAL' && actor.authUserId) {
      where.createdByUserId = actor.authUserId;
    }

    if (q) {
      where.OR = [
        { email: { contains: q, mode: 'insensitive' as const } },
        { firstName: { contains: q, mode: 'insensitive' as const } },
        { lastName: { contains: q, mode: 'insensitive' as const } },
        { phoneNumber: { contains: q, mode: 'insensitive' as const } },
        { doctorId: { contains: q, mode: 'insensitive' as const } },
      ];
    }

    const [items, total] = await Promise.all([
      this.prisma.doctorOnboardingInvite.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.doctorOnboardingInvite.count({ where }),
    ]);

    const doctorIds = Array.from(new Set(items.map((it) => it.doctorId).filter(Boolean)));
    const onboardingByDoctorId = await this.fetchOnboardingInfoByDoctorIds(doctorIds);

    return {
      items: items.map((it) => ({
        id: it.id,
        doctorId: it.doctorId,
        email: it.email,
        phoneNumber: it.phoneNumber ?? null,
        firstName: it.firstName ?? null,
        lastName: it.lastName ?? null,
        status: it.status,
        preferredPlanCode: it.preferredPlanCode ?? null,
        trialDurationValue: it.trialDurationValue ?? null,
        trialDurationUnit: it.trialDurationUnit ?? null,
        expiresAt: it.expiresAt.toISOString(),
        createdAt: it.createdAt.toISOString(),
        updatedAt: it.updatedAt.toISOString(),
        onboarding: onboardingByDoctorId.get(it.doctorId) ?? null,
      })),
      page,
      limit,
      total,
    };
  }

  async createInvite(dto: CreateDoctorOnboardingInviteDto, actor?: OnboardingActor) {
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber?.trim() || null;
    const trimmedFirstName = dto.firstName?.trim();
    const trimmedLastName = dto.lastName?.trim();

    if (!trimmedFirstName || !trimmedLastName) {
      throw new BadRequestException('Nombre y apellido son obligatorios');
    }

    const profile = this.normalizeProfile((dto.profile ?? {}) as PrefillProfile);

    if (!profile.specialties || profile.specialties.length < 1) {
      throw new BadRequestException('Selecciona al menos una especialidad');
    }

    const existingAccount = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
      select: { id: true },
    });
    if (existingAccount) {
      throw new ConflictException('El email ya esta registrado');
    }
    if (normalizedPhone) {
      const existingPhone = await this.prisma.account.findUnique({
        where: { phoneNumber: normalizedPhone },
        select: { id: true },
      });
      if (existingPhone) {
        throw new ConflictException('El telefono ya esta registrado');
      }
    }

    const doctorId = randomUUID();
    const authUserId = `prefill-${randomUUID()}`;
    const inviteToken = randomBytes(48).toString('hex');
    const tokenHash = this.hashToken(inviteToken);
    const expiresAt = new Date(Date.now() + this.inviteTtlMs);
    const settings = await this.getOrCreateSettings();
    const inviteTrial = {
      value: settings.inviteTrialDurationValue,
      unit: settings.inviteTrialDurationUnit,
    };

    await this.createPrefillDoctor({
      doctorId,
      authUserId,
      email: normalizedEmail,
      phoneNumber: normalizedPhone,
      firstName: trimmedFirstName,
      lastName: trimmedLastName,
    });

    const address = (dto.address ?? {}) as PrefillAddress;
    const agenda = (dto.agenda ?? {}) as PrefillAgenda;
    const services = (dto.services ?? []) as PrefillService[];

    if (Object.keys(profile).length) {
      await this.saveProfileDraft(doctorId, profile);
    }

    let agendaId: string | null = null;
    if (address.city && address.address) {
      const locationId = await this.upsertLocation(doctorId, {
        ...address,
        isPrimary: true,
      });
      if (locationId) {
        agendaId = await this.getAgendaIdForLocation(locationId);
      }
    }

    if (agendaId && agenda?.workingHours?.length) {
      await this.replaceWorkingHours(doctorId, agendaId, agenda.workingHours);
    }

    if (agendaId && services.length) {
      await this.replaceServices(doctorId, agendaId, services);
    }

    const invite = await this.prisma.doctorOnboardingInvite.create({
      data: {
        doctorId,
        email: normalizedEmail,
        phoneNumber: normalizedPhone,
        firstName: trimmedFirstName,
        lastName: trimmedLastName,
        tokenHash,
        status: InviteStatus.PENDING,
        expiresAt,
        preferredPlanCode: dto.planCode ?? null,
        trialDurationValue: inviteTrial?.value ?? null,
        trialDurationUnit: inviteTrial?.unit ?? null,
        createdByUserId: actor?.authUserId ?? null,
      },
    });

    if (dto.referralId && actor?.authUserId && actor.role === 'COMERCIAL') {
      await this.referrals.linkReferralToOnboardingInvite({
        referralId: dto.referralId,
        salesRepId: actor.authUserId,
        doctorId,
        onboardingInviteId: invite.id,
      });
    }

    await this.rabbitmq.publishAuthEvent({
      type: 'DoctorOnboardingInviteCreated',
      routingKey: 'auth.doctor_onboarding_invite_created',
      data: {
        authUserId,
        doctorId,
        email: normalizedEmail,
        phoneNumber: normalizedPhone ?? undefined,
        firstName: trimmedFirstName,
        lastName: trimmedLastName,
        inviteToken,
        preferredPlanCode: dto.planCode ?? undefined,
        trialDurationValue: inviteTrial?.value,
        trialDurationUnit: inviteTrial?.unit,
      },
    });

    return {
      inviteToken,
      expiresAt: expiresAt.toISOString(),
      doctorId,
    };
  }

  async createPublicDoctor(dto: CreatePublicDoctorDto, _actor?: OnboardingActor) {
    const trimmedFirstName = dto.firstName?.trim();
    const trimmedLastName = dto.lastName?.trim();

    if (!trimmedFirstName || !trimmedLastName) {
      throw new BadRequestException('Nombre y apellido son obligatorios');
    }

    const profile = this.normalizeProfile((dto.profile ?? {}) as PrefillProfile);
    if (!profile.specialties || profile.specialties.length < 1) {
      throw new BadRequestException('Selecciona al menos una especialidad');
    }

    const doctorId = randomUUID();
    const authUserId = `prefill-${randomUUID()}`;
    const normalizedEmail = this.buildNoContactEmail(trimmedFirstName, trimmedLastName, doctorId);

    await this.createPrefillDoctor({
      doctorId,
      authUserId,
      email: normalizedEmail,
      phoneNumber: null,
      firstName: trimmedFirstName,
      lastName: trimmedLastName,
    });

    const address = (dto.address ?? {}) as PrefillAddress;
    const agenda = (dto.agenda ?? {}) as PrefillAgenda;
    const services = (dto.services ?? []) as PrefillService[];

    if (Object.keys(profile).length) {
      await this.saveProfileDraft(doctorId, profile);
    }

    let agendaId: string | null = null;
    if (address.city && address.address) {
      const locationId = await this.upsertLocation(doctorId, {
        ...address,
        isPrimary: true,
      });
      if (locationId) {
        agendaId = await this.getAgendaIdForLocation(locationId);
      }
    }

    if (agendaId && agenda?.workingHours?.length) {
      await this.replaceWorkingHours(doctorId, agendaId, agenda.workingHours);
    }

    if (agendaId && services.length) {
      await this.replaceServices(doctorId, agendaId, services);
    }

    return {
      doctorId,
      email: normalizedEmail,
    };
  }

  async getInvitePrefill(token: string) {
    const invite = await this.findInviteByToken(token);
    return {
      email: invite.email,
      phoneNumber: invite.phoneNumber ?? null,
      firstName: invite.firstName ?? null,
      lastName: invite.lastName ?? null,
      expiresAt: invite.expiresAt.toISOString(),
      status: invite.status,
    };
  }

  async resendInvite(token: string) {
    const invite = await this.findInviteByToken(token);
    if (invite.status !== InviteStatus.PENDING) {
      throw new BadRequestException('Invitacion invalida');
    }
    if (invite.expiresAt < new Date()) {
      await this.prisma.doctorOnboardingInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.EXPIRED },
      });
      throw new BadRequestException('Invitacion expirada');
    }

    await this.rabbitmq.publishAuthEvent({
      type: 'DoctorOnboardingInviteCreated',
      routingKey: 'auth.doctor_onboarding_invite_created',
      data: {
        authUserId: invite.authUserId ?? undefined,
        doctorId: invite.doctorId,
        email: invite.email,
        phoneNumber: invite.phoneNumber ?? undefined,
        firstName: invite.firstName ?? undefined,
        lastName: invite.lastName ?? undefined,
        inviteToken: token,
        preferredPlanCode: invite.preferredPlanCode ?? undefined,
        trialDurationValue: invite.trialDurationValue ?? undefined,
        trialDurationUnit: invite.trialDurationUnit ?? undefined,
      },
    });

    return { sent: true };
  }

  async getPreferredPlanByDoctor(doctorId: string) {
    const invite = await this.prisma.doctorOnboardingInvite.findFirst({
      where: { doctorId, status: InviteStatus.ACCEPTED },
      select: {
        preferredPlanCode: true,
        trialDurationValue: true,
        trialDurationUnit: true,
      },
    });
    return {
      planCode: invite?.preferredPlanCode ?? null,
      trialDurationValue: invite?.trialDurationValue ?? null,
      trialDurationUnit: invite?.trialDurationUnit ?? null,
    };
  }

  async getSettings() {
    const settings = await this.getOrCreateSettings();
    return {
      inviteTrialDurationValue: settings.inviteTrialDurationValue,
      inviteTrialDurationUnit: settings.inviteTrialDurationUnit,
      updatedAt: settings.updatedAt.toISOString(),
    };
  }

  async updateSettings(dto: UpdateDoctorOnboardingSettingsDto, authUserId?: string) {
    const normalizedUnit = this.normalizeTrialDurationUnit(dto.inviteTrialDurationUnit);
    const settings = await this.prisma.doctorOnboardingSettings.upsert({
      where: { id: 'default' },
      create: {
        id: 'default',
        inviteTrialDurationValue: dto.inviteTrialDurationValue,
        inviteTrialDurationUnit: normalizedUnit,
        updatedByUserId: authUserId ?? null,
      },
      update: {
        inviteTrialDurationValue: dto.inviteTrialDurationValue,
        inviteTrialDurationUnit: normalizedUnit,
        updatedByUserId: authUserId ?? null,
      },
    });
    return {
      inviteTrialDurationValue: settings.inviteTrialDurationValue,
      inviteTrialDurationUnit: settings.inviteTrialDurationUnit,
      updatedAt: settings.updatedAt.toISOString(),
    };
  }

  async markInviteAccepted(token: string, authUserId: string) {
    const invite = await this.findInviteByToken(token);
    if (invite.status !== InviteStatus.PENDING) {
      return invite;
    }
    const updated = await this.prisma.doctorOnboardingInvite.update({
      where: { id: invite.id },
      data: {
        status: InviteStatus.ACCEPTED,
        authUserId,
      },
    });
    void this.rabbitmq.publishAuthEvent({
      type: 'DoctorAccountRegistered',
      routingKey: 'auth.doctor_account_registered',
      data: { doctorId: updated.doctorId },
    });
    return updated;
  }

  async resolveInviteForRegister(token: string, normalizedEmail: string) {
    const invite = await this.findInviteByToken(token);
    if (invite.status !== InviteStatus.PENDING) {
      if (invite.status === InviteStatus.ACCEPTED) {
        throw new BadRequestException('Invitacion ya fue aceptada');
      }
      if (invite.status === InviteStatus.REVOKED) {
        throw new BadRequestException('Invitacion revocada');
      }
      if (invite.status === InviteStatus.EXPIRED) {
        throw new BadRequestException('Invitacion expirada');
      }
      throw new BadRequestException('Invitacion invalida');
    }
    if (invite.expiresAt < new Date()) {
      await this.prisma.doctorOnboardingInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.EXPIRED },
      });
      throw new BadRequestException('Invitacion expirada');
    }
    if (invite.email !== normalizedEmail) {
      throw new BadRequestException('El email no coincide con la invitacion');
    }
    return invite;
  }

  private async findInviteByToken(token: string) {
    const tokenHash = this.hashToken(token.trim());
    const invite = await this.prisma.doctorOnboardingInvite.findUnique({
      where: { tokenHash },
    });
    if (!invite) {
      throw new NotFoundException('Invitacion no encontrada');
    }
    return invite;
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  private normalizeTrialDurationUnit(unit: 'DAY' | 'MONTH'): TrialDurationUnit {
    const normalizedUnit =
      unit.trim().toUpperCase() === TrialDurationUnit.DAY
        ? TrialDurationUnit.DAY
        : unit.trim().toUpperCase() === TrialDurationUnit.MONTH
          ? TrialDurationUnit.MONTH
          : null;
    if (!normalizedUnit) {
      throw new BadRequestException('trialDurationUnit debe ser DAY o MONTH');
    }
    return normalizedUnit;
  }

  private async getOrCreateSettings() {
    return this.prisma.doctorOnboardingSettings.upsert({
      where: { id: 'default' },
      create: {
        id: 'default',
        inviteTrialDurationValue: 1,
        inviteTrialDurationUnit: TrialDurationUnit.MONTH,
      },
      update: {},
    });
  }

  private normalizeProfile(profile: PrefillProfile) {
    const normalizeText = (value?: string) => {
      const trimmed = value?.trim();
      return trimmed ? trimmed : undefined;
    };
    const normalizeList = (values?: string[]) => {
      if (!values) return undefined;
      const cleaned = values.map((value) => value.trim()).filter(Boolean);
      return cleaned.length ? cleaned : undefined;
    };

    const cleanedDocument = profile.documentNumber
      ? profile.documentNumber.replace(/\D/g, '')
      : '';

    return {
      firstName: normalizeText(profile.firstName),
      lastName: normalizeText(profile.lastName),
      secondLastName: normalizeText(profile.secondLastName),
      gender: normalizeText(profile.gender),
      documentNumber: cleanedDocument.length >= 4 ? cleanedDocument : undefined,
      birthCity: normalizeText(profile.birthCity),
      birthProvince: normalizeText(profile.birthProvince),
      nationality: normalizeText(profile.nationality),
      bio: normalizeText(profile.bio),
      specialties: normalizeList(profile.specialties),
    };
  }

  private async createPrefillDoctor(payload: {
    doctorId: string;
    authUserId: string;
    email: string;
    phoneNumber?: string | null;
    firstName: string;
    lastName: string;
  }) {
    const fullName = `${payload.firstName} ${payload.lastName}`.trim();
    const response = await fetch(`${this.doctorsBaseUrl.replace(/\/$/, '')}/internal/prefill`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-role': 'SYSTEM' },
      body: JSON.stringify({
        doctorId: payload.doctorId,
        authUserId: payload.authUserId,
        email: payload.email,
        phoneNumber: payload.phoneNumber ?? undefined,
        fullName,
      }),
    });
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new BadRequestException(`No se pudo precrear el doctor: ${body}`);
    }
  }

  private async saveProfileDraft(doctorId: string, profile: PrefillProfile) {
    const response = await fetch(
      `${this.doctorsBaseUrl.replace(/\/$/, '')}/internal/doctors/${doctorId}/onboarding/profile/draft`,
      {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'x-role': 'SYSTEM' },
        body: JSON.stringify(profile),
      },
    );
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new BadRequestException(`No se pudo guardar el perfil: ${body}`);
    }
  }

  private buildNoContactEmail(firstName: string, lastName: string, doctorId: string) {
    const normalize = (value: string) =>
      value
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9]+/g, '.')
        .replace(/\.+/g, '.')
        .replace(/^\.|\.$/g, '')
        .toLowerCase();
    const safeFirst = normalize(firstName) || 'doctor';
    const safeLast = normalize(lastName) || 'nocontact';
    const suffix = doctorId.replace(/-/g, '').slice(0, 6);
    return `${safeFirst}.${safeLast}+nocontact.${suffix}@meudoc.co`;
  }

  private async upsertLocation(doctorId: string, address: PrefillAddress & { isPrimary?: boolean }) {
    const response = await fetch(
      `${this.doctorsBaseUrl.replace(/\/$/, '')}/doctors/${doctorId}/locations`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-role': 'SYSTEM' },
        body: JSON.stringify(address),
      },
    );
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new BadRequestException(`No se pudo guardar la direccion: ${body}`);
    }
    const data = (await response.json()) as { locationId?: string };
    return data.locationId ?? null;
  }

  private async getAgendaIdForLocation(locationId: string) {
    const response = await fetch(
      `${this.doctorsBaseUrl.replace(/\/$/, '')}/locations/${locationId}`,
      {
        headers: { 'x-role': 'SYSTEM' },
      },
    );
    if (!response.ok) {
      const body = await response.text().catch(() => '');
      throw new BadRequestException(`No se pudo cargar la agenda: ${body}`);
    }
    const data = (await response.json()) as { agendaId?: string | null };
    return data.agendaId ?? null;
  }

  private async replaceWorkingHours(
    doctorId: string,
    agendaId: string,
    rules: PrefillAgendaRule[],
  ) {
    const listUrl = `${this.availabilityBaseUrl.replace(/\/$/, '')}/availability/doctors/${doctorId}/working-hours?agendaId=${encodeURIComponent(agendaId)}`;
    const listResponse = await fetch(listUrl);
    if (listResponse.ok) {
      const existing = (await listResponse.json()) as Array<{ id: string }>;
      await Promise.all(
        existing.map((rule) =>
          fetch(
            `${this.availabilityBaseUrl.replace(/\/$/, '')}/availability/working-hours/${rule.id}`,
            { method: 'DELETE', headers: { 'x-role': 'SYSTEM' } },
          ),
        ),
      );
    }

    const agendaInfo = await fetch(
      `${this.availabilityBaseUrl.replace(/\/$/, '')}/availability/agendas/${agendaId}`,
      { headers: { 'x-role': 'SYSTEM' } },
    ).then((res) => res.ok ? res.json() : null);
    const timezone = agendaInfo?.timezone ?? 'America/Bogota';

    for (const rule of rules) {
      await fetch(
        `${this.availabilityBaseUrl.replace(/\/$/, '')}/availability/doctors/${doctorId}/working-hours`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'x-role': 'SYSTEM' },
          body: JSON.stringify({
            agendaId,
            dayOfWeek: rule.dayOfWeek,
            startTime: rule.startTime,
            endTime: rule.endTime,
            slotMinutes: rule.slotMinutes ?? 30,
            timezone,
            active: true,
            showProfileOnline: true,
            patientType: 'INSURANCE_AND_PRIVATE',
            patientStatus: 'ALL',
            repeatIntervalWeeks: 1,
            allServices: true,
            insurerIds: [],
            serviceIds: [],
          }),
        },
      );
    }
  }

  private async replaceServices(
    doctorId: string,
    agendaId: string,
    services: PrefillService[],
  ) {
    const listUrl = `${this.servicesBaseUrl.replace(/\/$/, '')}/doctors/${doctorId}/services`;
    const listResponse = await fetch(listUrl, { headers: { 'x-role': 'SYSTEM' } });
    if (listResponse.ok) {
      const existing = (await listResponse.json()) as Array<{ id: string }>;
      await Promise.all(
        existing.map((service) =>
          fetch(`${this.servicesBaseUrl.replace(/\/$/, '')}/services/${service.id}`, {
            method: 'DELETE',
            headers: { 'x-role': 'SYSTEM' },
          }),
        ),
      );
    }

    for (const service of services) {
      await fetch(`${this.servicesBaseUrl.replace(/\/$/, '')}/doctors/${doctorId}/services`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-role': 'SYSTEM' },
        body: JSON.stringify({
          name: service.name,
          modality: 'Presencial',
          durationMinutes: service.durationMinutes,
          agendaIds: [agendaId],
          showInMeuSalud: service.showInMeuSalud ?? true,
          reserveOnline: service.reserveOnline ?? true,
          priceAmount: service.priceAmount ?? undefined,
          currency: service.priceAmount !== undefined ? (service.currency ?? 'COP') : undefined,
        }),
      });
    }
  }

  private async fetchOnboardingInfoByDoctorIds(doctorIds: string[]) {
    const map = new Map<string, DoctorOnboardingInviteOnboardingInfo>();
    if (!doctorIds.length) return map;

    try {
      const url = `${this.doctorsInternalBaseUrl.replace(/\/$/, '')}/internal/doctors/onboarding/steps`;
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-role': 'SYSTEM' },
        body: JSON.stringify({ doctorIds }),
      });
      if (!response.ok) {
        return map;
      }
      const data = (await response.json()) as {
        items?: Array<{ doctorId: string; status?: string | null; profileStatus?: string | null; onboardingStep?: string | null }>;
      };
      for (const item of data.items ?? []) {
        if (!item?.doctorId) continue;
        map.set(String(item.doctorId), {
          doctorId: String(item.doctorId),
          status: item.status ?? null,
          profileStatus: item.profileStatus ?? null,
          onboardingStep: item.onboardingStep ?? null,
        });
      }
    } catch {
      return map;
    }

    return map;
  }
}
