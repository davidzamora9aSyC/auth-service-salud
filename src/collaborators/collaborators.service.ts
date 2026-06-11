import {
  BadRequestException,
  Injectable,
  NotFoundException,
  OnModuleInit,
} from '@nestjs/common';
import { createHash, randomBytes } from 'node:crypto';
import { AccountRole, CollaboratorStatus, InviteStatus } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { CreateCollaboratorInviteDto } from './dto/create-collaborator-invite.dto';
import { UpdateCollaboratorDto } from './dto/update-collaborator.dto';
import { PERMISSIONS_CATALOG } from './permissions.catalog';

const DEFAULT_INVITE_TTL_MINUTES = 60 * 24 * 7;

@Injectable()
export class CollaboratorsService implements OnModuleInit {
  constructor(private readonly prisma: PrismaService) {}

  async onModuleInit() {
    await this.syncPermissionsCatalog();
  }

  async createInvite(dto: CreateCollaboratorInviteDto) {
    const doctorId = dto.doctorId;
    if (!doctorId) {
      throw new BadRequestException('doctorId es requerido');
    }
    const normalizedEmail = dto.email.trim().toLowerCase();
    const normalizedPhone = dto.phoneNumber
      ? this.normalizePhoneNumber(dto.phoneNumber)
      : null;

    const existingAccount = await this.prisma.account.findUnique({
      where: { email: normalizedEmail },
      select: { role: true },
    });
    if (existingAccount?.role === AccountRole.DOCTOR) {
      throw new BadRequestException(
        'No se puede invitar como colaborador a un doctor ya registrado',
      );
    }
    const permissions = await this.resolvePermissions(dto.permissions);
    const token = this.generateToken();
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date(
      Date.now() +
        (dto.expiresInMinutes ?? DEFAULT_INVITE_TTL_MINUTES) * 60 * 1000,
    );

    const invite = await this.prisma.collaboratorInvite.create({
      data: {
        doctorId,
        email: normalizedEmail,
        phoneNumber: normalizedPhone,
        tokenHash,
        expiresAt,
        inviterAccountId: dto.inviterAccountId ?? null,
        permissions: {
          create: permissions.map((permission) => ({
            permissionId: permission.id,
          })),
        },
        agendas: {
          create: (dto.agendaIds ?? []).map((agendaId) => ({
            agendaId,
          })),
        },
      },
      include: {
        permissions: { include: { permission: true } },
        agendas: true,
      },
    });

    return this.formatInvite(invite, token);
  }

  async getInviteByToken(token: string) {
    const invite = await this.findInviteByToken(token);
    if (invite.status !== InviteStatus.PENDING) {
      throw new BadRequestException('La invitacion no esta disponible');
    }
    if (invite.expiresAt < new Date()) {
      await this.prisma.collaboratorInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.EXPIRED },
      });
      throw new BadRequestException('La invitacion ha expirado');
    }
    return this.formatInvite(invite);
  }

  async listCollaborators(doctorId: string) {
    const collaborators = await this.prisma.collaborator.findMany({
      where: { doctorId },
      include: {
        account: true,
        permissions: { include: { permission: true } },
        agendas: true,
      },
      orderBy: { createdAt: 'desc' },
    });
    return collaborators.map((collaborator) => ({
      id: collaborator.id,
      accountId: collaborator.accountId,
      doctorId: collaborator.doctorId,
      status: collaborator.status,
      firstName: collaborator.firstName,
      lastName: collaborator.lastName,
      email: collaborator.account.email,
      phoneNumber: collaborator.account.phoneNumber,
      permissions: collaborator.permissions.map((entry) => entry.permission.key),
      agendaIds: collaborator.agendas.map((agenda) => agenda.agendaId),
      createdAt: collaborator.createdAt,
      updatedAt: collaborator.updatedAt,
    }));
  }

  async updateCollaborator(id: string, dto: UpdateCollaboratorDto) {
    const collaborator = await this.prisma.collaborator.findUnique({
      where: { id },
      include: { permissions: true, agendas: true },
    });
    if (!collaborator) {
      throw new NotFoundException('Colaborador no encontrado');
    }

    const permissions = dto.permissions
      ? await this.resolvePermissions(dto.permissions)
      : null;
    const agendaIds = dto.agendaIds ?? null;

    const updated = await this.prisma.$transaction(async (tx) => {
      const updatedCollaborator = await tx.collaborator.update({
        where: { id },
        data: {
          status: dto.status ?? undefined,
        },
      });
      if (permissions) {
        await tx.collaboratorPermission.deleteMany({
          where: { collaboratorId: id },
        });
        if (permissions.length > 0) {
          await tx.collaboratorPermission.createMany({
            data: permissions.map((permission) => ({
              collaboratorId: id,
              permissionId: permission.id,
            })),
          });
        }
      }
      if (agendaIds) {
        await tx.collaboratorAgenda.deleteMany({
          where: { collaboratorId: id },
        });
        if (agendaIds.length > 0) {
          await tx.collaboratorAgenda.createMany({
            data: agendaIds.map((agendaId) => ({
              collaboratorId: id,
              agendaId,
            })),
          });
        }
      }
      return updatedCollaborator;
    });

    return {
      id: updated.id,
      status: updated.status,
    };
  }

  async disableCollaborator(id: string) {
    const collaborator = await this.prisma.collaborator.findUnique({
      where: { id },
    });
    if (!collaborator) {
      throw new NotFoundException('Colaborador no encontrado');
    }
    return this.prisma.collaborator.update({
      where: { id },
      data: { status: CollaboratorStatus.DISABLED },
    });
  }

  async resolveDoctorId(params: {
    doctorId?: string;
    subjectId?: string;
    authUserId?: string;
  }) {
    if (params.doctorId) {
      return params.doctorId;
    }
    if (params.subjectId) {
      return params.subjectId;
    }
    if (params.authUserId) {
      const account = await this.prisma.account.findUnique({
        where: { id: params.authUserId },
        select: { doctorId: true, subjectId: true },
      });
      const resolved = account?.doctorId ?? account?.subjectId ?? undefined;
      if (resolved) {
        return resolved;
      }
    }
    throw new BadRequestException('x-subject-id es requerido');
  }

  private async findInviteByToken(token: string) {
    const tokenHash = this.hashToken(token);
    const invite = await this.prisma.collaboratorInvite.findUnique({
      where: { tokenHash },
      include: {
        permissions: { include: { permission: true } },
        agendas: true,
      },
    });
    if (!invite) {
      throw new BadRequestException('Invitacion invalida');
    }
    return invite;
  }

  private async resolvePermissions(keys: string[]) {
    if (!keys.length) {
      return [];
    }
    const permissions = await this.prisma.permission.findMany({
      where: { key: { in: keys } },
    });
    const foundKeys = new Set(permissions.map((permission) => permission.key));
    const missing = keys.filter((key) => !foundKeys.has(key));
    if (missing.length > 0) {
      throw new BadRequestException(
        `Permisos invalidos: ${missing.join(', ')}`,
      );
    }
    return permissions;
  }

  private async syncPermissionsCatalog() {
    await Promise.all(
      PERMISSIONS_CATALOG.map((permission) =>
        this.prisma.permission.upsert({
          where: { key: permission.key },
          update: {
            name: permission.name,
            description: permission.description ?? null,
          },
          create: {
            key: permission.key,
            name: permission.name,
            description: permission.description ?? null,
          },
        }),
      ),
    );
  }

  private generateToken() {
    return randomBytes(32).toString('hex');
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }

  private normalizePhoneNumber(value: string) {
    const trimmed = value.replace(/[\s.-]/g, '');
    if (!trimmed.startsWith('+')) {
      return `+${trimmed}`;
    }
    return trimmed;
  }

  private formatInvite(invite: {
    id: string;
    doctorId: string;
    email: string;
    phoneNumber: string | null;
    expiresAt: Date;
    status: InviteStatus;
    permissions: Array<{ permission: { key: string } }>;
    agendas: Array<{ agendaId: string }>;
  }, token?: string) {
    return {
      id: invite.id,
      doctorId: invite.doctorId,
      email: invite.email,
      phoneNumber: invite.phoneNumber ?? undefined,
      expiresAt: invite.expiresAt.toISOString(),
      status: invite.status,
      permissions: invite.permissions.map((entry) => entry.permission.key),
      agendaIds: invite.agendas.map((agenda) => agenda.agendaId),
      token,
    };
  }
}
