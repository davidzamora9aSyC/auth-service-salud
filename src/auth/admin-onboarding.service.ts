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
import { InviteStatus } from '@prisma/client';
import { CreateDoctorOnboardingInviteDto } from './dto/create-doctor-onboarding-invite.dto';
import { RabbitmqService } from './rabbitmq.service';

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
  private readonly availabilityBaseUrl: string;
  private readonly servicesBaseUrl: string;
  private readonly inviteTtlMs: number;

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly rabbitmq: RabbitmqService,
  ) {
    this.doctorsBaseUrl =
      this.config.get<string>('DOCTORS_BASE_URL') ??
      'http://doctors-service:3009/doctorsms';
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

  async createInvite(dto: CreateDoctorOnboardingInviteDto) {
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

    await this.prisma.doctorOnboardingInvite.create({
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
      },
    });

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
      },
    });

    return {
      inviteToken,
      expiresAt: expiresAt.toISOString(),
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
      },
    });

    return { sent: true };
  }

  async getPreferredPlanByDoctor(doctorId: string) {
    const invite = await this.prisma.doctorOnboardingInvite.findFirst({
      where: { doctorId, status: InviteStatus.ACCEPTED },
      select: { preferredPlanCode: true },
    });
    return { planCode: invite?.preferredPlanCode ?? null };
  }

  async markInviteAccepted(token: string, authUserId: string) {
    const invite = await this.findInviteByToken(token);
    if (invite.status !== InviteStatus.PENDING) {
      return invite;
    }
    return this.prisma.doctorOnboardingInvite.update({
      where: { id: invite.id },
      data: {
        status: InviteStatus.ACCEPTED,
        authUserId,
      },
    });
  }

  async resolveInviteForRegister(token: string, normalizedEmail: string) {
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
}
