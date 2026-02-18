import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import {
  AccountRole,
  ClinicAdminRole,
  ClinicDoctorMembershipStatus,
  InviteStatus,
} from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { CreateClinicDto } from './dto/create-clinic.dto';
import { UpdateClinicDto } from './dto/update-clinic.dto';
import { InviteClinicDoctorDto } from './dto/invite-clinic-doctor.dto';
import { AddClinicAdminDto } from './dto/add-clinic-admin.dto';
import { CreateClinicLocationDto } from './dto/create-clinic-location.dto';
import { UpdateClinicLocationDto } from './dto/update-clinic-location.dto';
import { AssignClinicAgendaDto } from './dto/assign-clinic-agenda.dto';

const DEFAULT_INVITE_TTL_MINUTES = 60 * 24 * 7;

type Actor = {
  role?: string;
  authUserId?: string;
  subjectId?: string;
};

@Injectable()
export class ClinicsService {
  constructor(private readonly prisma: PrismaService) {}

  async createClinic(dto: CreateClinicDto, actor: Actor) {
    this.ensureCanCreateClinic(actor);
    const authUserId = this.requireAuthUserId(actor);

    const clinic = await this.prisma.clinic.create({
      data: {
        name: dto.name.trim(),
        legalName: dto.legalName?.trim() || null,
        taxId: dto.taxId?.trim() || null,
        description: dto.description?.trim() || null,
        website: dto.website?.trim() || null,
        phoneNumber: dto.phoneNumber?.trim() || null,
        email: dto.email?.trim().toLowerCase() || null,
        createdByAccountId: authUserId,
        admins: {
          create: {
            accountId: authUserId,
            role: ClinicAdminRole.OWNER,
            active: true,
          },
        },
      },
      include: {
        admins: true,
      },
    });

    return {
      id: clinic.id,
      name: clinic.name,
      legalName: clinic.legalName,
      createdAt: clinic.createdAt,
    };
  }

  async getClinic(clinicId: string, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    const clinic = await this.prisma.clinic.findUnique({
      where: { id: clinicId },
      include: {
        admins: {
          where: { active: true },
          include: {
            account: {
              select: { id: true, email: true },
            },
          },
        },
      },
    });
    if (!clinic) {
      throw new NotFoundException('Clinica no encontrada');
    }

    return {
      id: clinic.id,
      name: clinic.name,
      legalName: clinic.legalName,
      taxId: clinic.taxId,
      description: clinic.description,
      website: clinic.website,
      phoneNumber: clinic.phoneNumber,
      email: clinic.email,
      profileImageId: clinic.profileImageId,
      coverImageId: clinic.coverImageId,
      admins: clinic.admins.map((admin) => ({
        accountId: admin.accountId,
        email: admin.account.email,
        role: admin.role,
      })),
      createdAt: clinic.createdAt,
      updatedAt: clinic.updatedAt,
    };
  }

  async updateClinic(clinicId: string, dto: UpdateClinicDto, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);

    const updated = await this.prisma.clinic.update({
      where: { id: clinicId },
      data: {
        name: dto.name?.trim() || undefined,
        legalName: dto.legalName?.trim() || undefined,
        taxId: dto.taxId?.trim() || undefined,
        description: dto.description?.trim() || undefined,
        website: dto.website?.trim() || undefined,
        phoneNumber: dto.phoneNumber?.trim() || undefined,
        email: dto.email?.trim().toLowerCase() || undefined,
        profileImageId: dto.profileImageId === undefined ? undefined : dto.profileImageId,
        coverImageId: dto.coverImageId === undefined ? undefined : dto.coverImageId,
      },
    });

    return {
      id: updated.id,
      updatedAt: updated.updatedAt,
    };
  }

  async addClinicAdmin(clinicId: string, dto: AddClinicAdminDto, actor: Actor) {
    await this.ensureClinicOwnerAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);

    const account = await this.prisma.account.findUnique({
      where: { email: dto.email.trim().toLowerCase() },
      select: { id: true, status: true },
    });
    if (!account) {
      throw new NotFoundException('Cuenta no encontrada');
    }

    await this.prisma.clinicAdmin.upsert({
      where: {
        clinicId_accountId: {
          clinicId,
          accountId: account.id,
        },
      },
      update: {
        active: true,
        role: dto.role === 'OWNER' ? ClinicAdminRole.OWNER : ClinicAdminRole.ADMIN,
      },
      create: {
        clinicId,
        accountId: account.id,
        active: true,
        role: dto.role === 'OWNER' ? ClinicAdminRole.OWNER : ClinicAdminRole.ADMIN,
      },
    });

    return { ok: true };
  }

  async inviteDoctor(clinicId: string, dto: InviteClinicDoctorDto, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);
    const inviterAccountId = this.requireAuthUserId(actor);

    const normalizedEmail = dto.doctorEmail.trim().toLowerCase();
    const doctorAccount = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
      select: { id: true, role: true, doctorId: true },
    });
    if (!doctorAccount || doctorAccount.role !== AccountRole.DOCTOR || !doctorAccount.doctorId) {
      throw new BadRequestException('El email no corresponde a un medico registrado');
    }

    const existingMembership = await this.prisma.clinicDoctorMembership.findUnique({
      where: {
        clinicId_doctorId: {
          clinicId,
          doctorId: doctorAccount.doctorId,
        },
      },
      select: { status: true },
    });
    if (existingMembership?.status === ClinicDoctorMembershipStatus.ACTIVE) {
      throw new BadRequestException('El medico ya esta afiliado a esta clinica');
    }

    const token = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date(Date.now() + DEFAULT_INVITE_TTL_MINUTES * 60 * 1000);

    const invite = await this.prisma.clinicDoctorInvite.create({
      data: {
        clinicId,
        doctorId: doctorAccount.doctorId,
        email: normalizedEmail,
        tokenHash,
        expiresAt,
        inviterAccountId,
      },
    });

    return {
      id: invite.id,
      clinicId,
      doctorId: invite.doctorId,
      email: invite.email,
      status: invite.status,
      expiresAt: invite.expiresAt.toISOString(),
      token,
    };
  }

  async listDoctorInvites(clinicId: string, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);

    const invites = await this.prisma.clinicDoctorInvite.findMany({
      where: { clinicId },
      orderBy: { createdAt: 'desc' },
    });

    return invites.map((invite) => ({
      id: invite.id,
      clinicId: invite.clinicId,
      doctorId: invite.doctorId,
      email: invite.email,
      status: invite.status,
      expiresAt: invite.expiresAt.toISOString(),
      createdAt: invite.createdAt.toISOString(),
    }));
  }

  async acceptDoctorInvite(token: string, actor: Actor) {
    const normalizedRole = actor.role?.toUpperCase();
    if (normalizedRole !== 'DOCTOR') {
      throw new ForbiddenException('Solo un medico puede aceptar la invitacion');
    }
    const authUserId = this.requireAuthUserId(actor);

    const invite = await this.prisma.clinicDoctorInvite.findUnique({
      where: { tokenHash: this.hashToken(token) },
    });
    if (!invite || invite.status !== InviteStatus.PENDING) {
      throw new BadRequestException('Invitacion invalida');
    }
    if (invite.expiresAt < new Date()) {
      await this.prisma.clinicDoctorInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.EXPIRED },
      });
      throw new BadRequestException('Invitacion expirada');
    }

    const account = await this.prisma.account.findUnique({
      where: { id: authUserId },
      select: { doctorId: true },
    });
    if (!account?.doctorId || account.doctorId !== invite.doctorId) {
      throw new ForbiddenException('La invitacion no pertenece al medico autenticado');
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.clinicDoctorMembership.upsert({
        where: {
          clinicId_doctorId: {
            clinicId: invite.clinicId,
            doctorId: invite.doctorId,
          },
        },
        update: {
          status: ClinicDoctorMembershipStatus.ACTIVE,
          createdByAccountId: authUserId,
        },
        create: {
          clinicId: invite.clinicId,
          doctorId: invite.doctorId,
          status: ClinicDoctorMembershipStatus.ACTIVE,
          createdByAccountId: authUserId,
        },
      });
      await tx.clinicDoctorInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.ACCEPTED },
      });
    });

    return { ok: true, clinicId: invite.clinicId, doctorId: invite.doctorId };
  }

  async listDoctors(clinicId: string, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);

    const memberships = await this.prisma.clinicDoctorMembership.findMany({
      where: {
        clinicId,
        status: ClinicDoctorMembershipStatus.ACTIVE,
      },
      orderBy: { createdAt: 'desc' },
    });

    return memberships.map((membership) => ({
      doctorId: membership.doctorId,
      status: membership.status,
      createdAt: membership.createdAt.toISOString(),
    }));
  }

  async removeDoctor(clinicId: string, doctorId: string, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);

    const membership = await this.prisma.clinicDoctorMembership.findUnique({
      where: {
        clinicId_doctorId: {
          clinicId,
          doctorId,
        },
      },
    });
    if (!membership) {
      throw new NotFoundException('Afiliacion no encontrada');
    }

    await this.prisma.clinicDoctorMembership.update({
      where: {
        clinicId_doctorId: {
          clinicId,
          doctorId,
        },
      },
      data: {
        status: ClinicDoctorMembershipStatus.REMOVED,
      },
    });

    return { ok: true };
  }

  async listLocations(clinicId: string, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);
    const locations = await this.prisma.clinicLocation.findMany({
      where: { clinicId },
      include: {
        agendaAssignments: {
          where: { active: true },
          orderBy: { createdAt: 'desc' },
        },
      },
      orderBy: [{ isPrimary: 'desc' }, { createdAt: 'desc' }],
    });
    return locations.map((location) => ({
      id: location.id,
      clinicId: location.clinicId,
      label: location.label,
      city: location.city,
      address: location.address,
      postalCode: location.postalCode,
      additionalInfo: location.additionalInfo,
      placeId: location.placeId,
      formattedAddress: location.formattedAddress,
      department: location.department,
      countryCode: location.countryCode,
      lat: location.lat,
      lng: location.lng,
      isPrimary: location.isPrimary,
      active: location.active,
      agendaAssignments: location.agendaAssignments.map((assignment) => ({
        agendaId: assignment.agendaId,
        doctorId: assignment.doctorId,
        active: assignment.active,
        createdAt: assignment.createdAt.toISOString(),
      })),
      createdAt: location.createdAt.toISOString(),
      updatedAt: location.updatedAt.toISOString(),
    }));
  }

  async createLocation(clinicId: string, dto: CreateClinicLocationDto, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    await this.ensureClinicExists(clinicId);
    const authUserId = this.requireAuthUserId(actor);

    const location = await this.prisma.$transaction(async (tx) => {
      if (dto.isPrimary) {
        await tx.clinicLocation.updateMany({
          where: { clinicId },
          data: { isPrimary: false },
        });
      }
      return tx.clinicLocation.create({
        data: {
          clinicId,
          label: dto.label?.trim() || null,
          city: dto.city.trim(),
          address: dto.address.trim(),
          postalCode: dto.postalCode?.trim() || null,
          additionalInfo: dto.additionalInfo?.trim() || null,
          placeId: dto.placeId?.trim() || null,
          formattedAddress: dto.formattedAddress?.trim() || null,
          department: dto.department?.trim() || null,
          countryCode: dto.countryCode?.trim() || null,
          lat: dto.lat ?? null,
          lng: dto.lng ?? null,
          isPrimary: Boolean(dto.isPrimary),
          active: true,
          createdByAccountId: authUserId,
        },
      });
    });

    return { locationId: location.id };
  }

  async updateLocation(
    clinicId: string,
    locationId: string,
    dto: UpdateClinicLocationDto,
    actor: Actor,
  ) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    const location = await this.ensureLocationBelongsToClinic(clinicId, locationId);

    await this.prisma.$transaction(async (tx) => {
      if (dto.isPrimary) {
        await tx.clinicLocation.updateMany({
          where: { clinicId },
          data: { isPrimary: false },
        });
      }
      await tx.clinicLocation.update({
        where: { id: location.id },
        data: {
          label: dto.label === undefined ? undefined : dto.label.trim() || null,
          city: dto.city === undefined ? undefined : dto.city.trim(),
          address: dto.address === undefined ? undefined : dto.address.trim(),
          postalCode: dto.postalCode === undefined ? undefined : dto.postalCode.trim() || null,
          additionalInfo:
            dto.additionalInfo === undefined ? undefined : dto.additionalInfo.trim() || null,
          placeId: dto.placeId === undefined ? undefined : dto.placeId.trim() || null,
          formattedAddress:
            dto.formattedAddress === undefined ? undefined : dto.formattedAddress.trim() || null,
          department: dto.department === undefined ? undefined : dto.department.trim() || null,
          countryCode:
            dto.countryCode === undefined ? undefined : dto.countryCode.trim() || null,
          lat: dto.lat === undefined ? undefined : dto.lat,
          lng: dto.lng === undefined ? undefined : dto.lng,
          isPrimary: dto.isPrimary ?? undefined,
          active: dto.active ?? undefined,
        },
      });
    });

    return { ok: true };
  }

  async deleteLocation(clinicId: string, locationId: string, actor: Actor) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    const location = await this.ensureLocationBelongsToClinic(clinicId, locationId);

    await this.prisma.$transaction(async (tx) => {
      await tx.clinicAgendaAssignment.deleteMany({
        where: { clinicLocationId: location.id },
      });
      await tx.clinicLocation.delete({
        where: { id: location.id },
      });
    });

    return { ok: true };
  }

  async assignAgenda(
    clinicId: string,
    locationId: string,
    dto: AssignClinicAgendaDto,
    actor: Actor,
  ) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    const location = await this.ensureLocationBelongsToClinic(clinicId, locationId);
    if (!location.active) {
      throw new BadRequestException('No se puede asignar agendas a una sede inactiva');
    }
    const authUserId = this.requireAuthUserId(actor);

    await this.ensureDoctorAffiliated(clinicId, dto.doctorId);

    const existingForAgenda = await this.prisma.clinicAgendaAssignment.findFirst({
      where: {
        agendaId: dto.agendaId,
        active: true,
      },
      select: { clinicLocationId: true },
    });
    if (existingForAgenda && existingForAgenda.clinicLocationId !== location.id) {
      throw new BadRequestException('La agenda ya esta asignada a otra sede');
    }

    await this.prisma.clinicAgendaAssignment.upsert({
      where: {
        clinicLocationId_agendaId: {
          clinicLocationId: location.id,
          agendaId: dto.agendaId,
        },
      },
      update: {
        doctorId: dto.doctorId,
        active: true,
        createdByAccountId: authUserId,
      },
      create: {
        clinicLocationId: location.id,
        agendaId: dto.agendaId,
        doctorId: dto.doctorId,
        active: true,
        createdByAccountId: authUserId,
      },
    });

    return { ok: true };
  }

  async unassignAgenda(
    clinicId: string,
    locationId: string,
    agendaId: string,
    actor: Actor,
  ) {
    await this.ensureClinicAdminAccess(clinicId, actor);
    const location = await this.ensureLocationBelongsToClinic(clinicId, locationId);
    const assignment = await this.prisma.clinicAgendaAssignment.findUnique({
      where: {
        clinicLocationId_agendaId: {
          clinicLocationId: location.id,
          agendaId,
        },
      },
    });
    if (!assignment) {
      throw new NotFoundException('Asignacion de agenda no encontrada');
    }
    await this.prisma.clinicAgendaAssignment.delete({
      where: {
        clinicLocationId_agendaId: {
          clinicLocationId: location.id,
          agendaId,
        },
      },
    });
    return { ok: true };
  }

  async getAgendaScope(agendaId: string, doctorId: string | undefined, actor: Actor) {
    const normalizedRole = actor.role?.toUpperCase();
    if (normalizedRole !== 'SYSTEM' && normalizedRole !== 'ADMIN') {
      throw new ForbiddenException('No autorizado');
    }

    const assignment = await this.prisma.clinicAgendaAssignment.findUnique({
      where: { agendaId },
      include: {
        clinicLocation: {
          select: {
            id: true,
            clinicId: true,
            active: true,
          },
        },
      },
    });

    if (!assignment || !assignment.active || !assignment.clinicLocation.active) {
      throw new NotFoundException('Scope de agenda no encontrado');
    }
    if (doctorId && assignment.doctorId !== doctorId) {
      throw new NotFoundException('Scope de agenda no encontrado');
    }

    return {
      clinicId: assignment.clinicLocation.clinicId,
      clinicLocationId: assignment.clinicLocation.id,
      doctorId: assignment.doctorId,
      agendaId: assignment.agendaId,
    };
  }

  private async ensureClinicExists(clinicId: string) {
    const clinic = await this.prisma.clinic.findUnique({
      where: { id: clinicId },
      select: { id: true },
    });
    if (!clinic) {
      throw new NotFoundException('Clinica no encontrada');
    }
  }

  private async ensureLocationBelongsToClinic(clinicId: string, locationId: string) {
    const location = await this.prisma.clinicLocation.findUnique({
      where: { id: locationId },
    });
    if (!location || location.clinicId !== clinicId) {
      throw new NotFoundException('Sede no encontrada');
    }
    return location;
  }

  private async ensureDoctorAffiliated(clinicId: string, doctorId: string) {
    const membership = await this.prisma.clinicDoctorMembership.findUnique({
      where: {
        clinicId_doctorId: {
          clinicId,
          doctorId,
        },
      },
      select: { status: true },
    });
    if (!membership || membership.status !== ClinicDoctorMembershipStatus.ACTIVE) {
      throw new BadRequestException('El medico no esta afiliado activamente a la clinica');
    }
  }

  private async ensureClinicAdminAccess(clinicId: string, actor: Actor) {
    const normalizedRole = actor.role?.toUpperCase();
    if (normalizedRole === 'ADMIN' || normalizedRole === 'SYSTEM') {
      return;
    }
    const authUserId = this.requireAuthUserId(actor);
    const admin = await this.prisma.clinicAdmin.findUnique({
      where: {
        clinicId_accountId: {
          clinicId,
          accountId: authUserId,
        },
      },
      select: { active: true },
    });
    if (!admin?.active) {
      throw new ForbiddenException('No autorizado');
    }
  }

  private async ensureClinicOwnerAccess(clinicId: string, actor: Actor) {
    const normalizedRole = actor.role?.toUpperCase();
    if (normalizedRole === 'ADMIN' || normalizedRole === 'SYSTEM') {
      return;
    }
    const authUserId = this.requireAuthUserId(actor);
    const admin = await this.prisma.clinicAdmin.findUnique({
      where: {
        clinicId_accountId: {
          clinicId,
          accountId: authUserId,
        },
      },
      select: { active: true, role: true },
    });
    if (!admin?.active || admin.role !== ClinicAdminRole.OWNER) {
      throw new ForbiddenException('Solo el owner de la clinica puede realizar esta accion');
    }
  }

  private ensureCanCreateClinic(actor: Actor) {
    const normalizedRole = actor.role?.toUpperCase();
    if (
      normalizedRole !== 'DOCTOR' &&
      normalizedRole !== 'ADMIN' &&
      normalizedRole !== 'SYSTEM'
    ) {
      throw new ForbiddenException('No autorizado para crear clinica');
    }
  }

  private requireAuthUserId(actor: Actor) {
    if (!actor.authUserId) {
      throw new BadRequestException('x-auth-user-id es requerido');
    }
    return actor.authUserId;
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }
}
