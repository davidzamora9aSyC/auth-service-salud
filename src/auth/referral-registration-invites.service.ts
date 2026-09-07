import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InviteStatus, ReferralType } from '@prisma/client';
import { createHash, randomBytes } from 'node:crypto';
import { PrismaService } from '../prisma/prisma.service';
import { RabbitmqService } from './rabbitmq.service';
import { CreateReferralRegistrationInviteDto } from './dto/create-referral-registration-invite.dto';
import {
  buildCompanyReferralInviteUrl,
  buildPatientReferralInviteUrl,
} from './referral-invite-url.util';

const DEFAULT_INVITE_TTL_MS = 1000 * 60 * 60 * 24 * 14;

type InviteActor = {
  role?: string;
  authUserId?: string;
};

@Injectable()
export class ReferralRegistrationInvitesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly rabbitmq: RabbitmqService,
  ) {}

  async createInvite(dto: CreateReferralRegistrationInviteDto, actor?: InviteActor) {
    if (dto.type === ReferralType.DOCTOR) {
      throw new BadRequestException('Las invitaciones de doctores usan el flujo de onboarding existente');
    }

    const email = dto.email.trim().toLowerCase();
    const phoneNumber = dto.phoneNumber.trim();
    const firstName = dto.firstName.trim();
    const lastName = dto.lastName.trim();
    const companyName = dto.companyName?.trim() || null;
    const taxId = dto.taxId?.trim() || null;

    if (!firstName || !lastName) {
      throw new BadRequestException('Nombre y apellido son obligatorios');
    }
    if (dto.type === ReferralType.COMPANY && (!companyName || !taxId)) {
      throw new BadRequestException('Nombre de empresa y NIT son obligatorios');
    }

    let referralId: string | null = dto.referralId?.trim() || null;
    if (referralId) {
      const referral = await this.prisma.doctorReferral.findUnique({
        where: { id: referralId },
        select: {
          id: true,
          salesRepId: true,
          referralType: true,
        },
      });
      if (!referral) {
        throw new NotFoundException('Referido no encontrado');
      }
      if (referral.referralType !== dto.type) {
        throw new BadRequestException('El tipo de invitacion no coincide con el tipo de referido');
      }
      if (actor?.role === 'COMERCIAL' && actor.authUserId && referral.salesRepId !== actor.authUserId) {
        throw new NotFoundException('Referido no encontrado');
      }
    }

    const token = randomBytes(32).toString('hex');
    const tokenHash = this.hashToken(token);
    const expiresAt = new Date(Date.now() + DEFAULT_INVITE_TTL_MS);

    const invite = referralId
      ? await this.prisma.referralRegistrationInvite.upsert({
          where: { referralId },
          update: {
            type: dto.type,
            email,
            phoneNumber,
            firstName,
            lastName,
            companyName,
            taxId,
            tokenHash,
            status: InviteStatus.PENDING,
            expiresAt,
            createdByUserId: actor?.authUserId ?? null,
            acceptedAuthUserId: null,
            acceptedSubjectId: null,
            lastSentAt: new Date(),
            lastSentChannel: 'EMAIL_WHATSAPP',
            sentCount: { increment: 1 },
          },
          create: {
            referralId,
            type: dto.type,
            email,
            phoneNumber,
            firstName,
            lastName,
            companyName,
            taxId,
            tokenHash,
            expiresAt,
            createdByUserId: actor?.authUserId ?? null,
            lastSentAt: new Date(),
            lastSentChannel: 'EMAIL_WHATSAPP',
            sentCount: 1,
          },
        })
      : await this.prisma.referralRegistrationInvite.create({
          data: {
            type: dto.type,
            email,
            phoneNumber,
            firstName,
            lastName,
            companyName,
            taxId,
            tokenHash,
            expiresAt,
            createdByUserId: actor?.authUserId ?? null,
            lastSentAt: new Date(),
            lastSentChannel: 'EMAIL_WHATSAPP',
            sentCount: 1,
          },
        });

    if (referralId) {
      await this.prisma.doctorReferral.update({
        where: { id: referralId },
        data: {
          status: 'ONBOARDING_SENT',
          fullName: `${firstName} ${lastName}`.trim(),
          phoneNumber,
          email,
          companyName,
          taxId,
        },
      });
    }

    const inviteUrl = this.buildInviteUrl({
      type: dto.type,
      token,
      firstName,
      lastName,
      email,
      phoneNumber,
      companyName,
      taxId,
    });

    await this.rabbitmq.publishAuthEvent({
      type: 'ReferralRegistrationInviteCreated',
      routingKey: 'auth.referral_registration_invite_created',
      data: {
        referralInviteId: invite.id,
        referralId: referralId ?? undefined,
        referralType: dto.type,
        email,
        phoneNumber,
        firstName,
        lastName,
        companyName: companyName ?? undefined,
        taxId: taxId ?? undefined,
        inviteToken: token,
        inviteUrl,
      },
    });

    return {
      inviteId: invite.id,
      inviteToken: token,
      inviteUrl,
      expiresAt: expiresAt.toISOString(),
      type: dto.type,
    };
  }

  async getInviteByToken(token: string) {
    const invite = await this.findInviteByToken(token);
    this.assertInviteAvailable(invite);
    return this.toInviteResponse(invite, token);
  }

  async resolveInviteForRegister(input: {
    token: string;
    role: 'PATIENT' | 'COMPANY';
    email: string;
    phoneNumber: string;
    companyName?: string;
    taxId?: string;
  }) {
    const invite = await this.findInviteByToken(input.token);
    this.assertInviteAvailable(invite);
    if (invite.type !== input.role) {
      throw new BadRequestException('La invitacion no aplica para este registro');
    }
    if (invite.email !== input.email) {
      throw new BadRequestException('El correo no coincide con la invitacion');
    }
    if (invite.phoneNumber !== input.phoneNumber) {
      throw new BadRequestException('El telefono no coincide con la invitacion');
    }
    if (invite.type === ReferralType.COMPANY) {
      if ((invite.taxId ?? '') !== (input.taxId?.trim() ?? '')) {
        throw new BadRequestException('El NIT no coincide con la invitacion');
      }
      if ((invite.companyName ?? '').toLowerCase() !== (input.companyName?.trim().toLowerCase() ?? '')) {
        throw new BadRequestException('La empresa no coincide con la invitacion');
      }
    }
    return invite;
  }

  async markInviteAccepted(token: string, authUserId: string, subjectId: string) {
    const invite = await this.findInviteByToken(token);
    if (invite.status === InviteStatus.ACCEPTED) {
      return invite;
    }
    const updated = await this.prisma.referralRegistrationInvite.update({
      where: { id: invite.id },
      data: {
        status: InviteStatus.ACCEPTED,
        acceptedAuthUserId: authUserId,
        acceptedSubjectId: subjectId,
      },
    });

    if (invite.referralId) {
      await this.prisma.doctorReferral.update({
        where: { id: invite.referralId },
        data:
          invite.type === ReferralType.PATIENT
            ? {
                patientId: subjectId,
                status: 'ACTIVE',
              }
            : {
                employerId: subjectId,
                status: 'ACCOUNT_CREATED',
              },
      });
    }

    return updated;
  }

  private buildInviteUrl(input: {
    type: ReferralType;
    token: string;
    firstName: string;
    lastName: string;
    email: string;
    phoneNumber: string;
    companyName: string | null;
    taxId: string | null;
  }) {
    if (input.type === ReferralType.PATIENT) {
      return buildPatientReferralInviteUrl({
        token: input.token,
        firstName: input.firstName,
        lastName: input.lastName,
        email: input.email,
        phoneNumber: input.phoneNumber,
      });
    }
    return buildCompanyReferralInviteUrl({
      token: input.token,
      firstName: input.firstName,
      lastName: input.lastName,
      email: input.email,
      phoneNumber: input.phoneNumber,
      companyName: input.companyName ?? '',
      taxId: input.taxId ?? '',
    });
  }

  private async findInviteByToken(token: string) {
    const tokenHash = this.hashToken(token);
    const invite = await this.prisma.referralRegistrationInvite.findUnique({
      where: { tokenHash },
    });
    if (!invite) {
      throw new NotFoundException('Invitacion no encontrada');
    }
    return invite;
  }

  private assertInviteAvailable(invite: {
    id: string;
    status: InviteStatus;
    expiresAt: Date;
  }) {
    if (invite.status !== InviteStatus.PENDING) {
      if (invite.status === InviteStatus.ACCEPTED) {
        throw new BadRequestException('Invitacion ya fue aceptada');
      }
      if (invite.status === InviteStatus.REVOKED) {
        throw new BadRequestException('Invitacion revocada');
      }
      throw new BadRequestException('Invitacion invalida');
    }
    if (invite.expiresAt < new Date()) {
      void this.prisma.referralRegistrationInvite.update({
        where: { id: invite.id },
        data: { status: InviteStatus.EXPIRED },
      });
      throw new BadRequestException('Invitacion expirada');
    }
  }

  private toInviteResponse(
    invite: {
      id: string;
      type: ReferralType;
      email: string;
      phoneNumber: string;
      firstName: string;
      lastName: string;
      companyName: string | null;
      taxId: string | null;
      status: InviteStatus;
      expiresAt: Date;
      referralId: string | null;
    },
    token: string,
  ) {
    return {
      id: invite.id,
      referralId: invite.referralId,
      type: invite.type,
      email: invite.email,
      phoneNumber: invite.phoneNumber,
      firstName: invite.firstName,
      lastName: invite.lastName,
      companyName: invite.companyName,
      taxId: invite.taxId,
      status: invite.status,
      expiresAt: invite.expiresAt.toISOString(),
      inviteUrl: this.buildInviteUrl({
        type: invite.type,
        token,
        firstName: invite.firstName,
        lastName: invite.lastName,
        email: invite.email,
        phoneNumber: invite.phoneNumber,
        companyName: invite.companyName,
        taxId: invite.taxId,
      }),
    };
  }

  private hashToken(token: string) {
    return createHash('sha256').update(token).digest('hex');
  }
}
