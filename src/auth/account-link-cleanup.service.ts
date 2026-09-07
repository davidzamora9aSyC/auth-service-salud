import { Injectable, Logger } from '@nestjs/common';
import { AccountRole, ProductCode, ProductRole } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AccountLinkCleanupService {
  private readonly logger = new Logger(AccountLinkCleanupService.name);
  private readonly doctorPortalRoles = [
    ProductRole.DOCTOR,
    ProductRole.RESEARCHER,
    ProductRole.STUDENT,
  ];

  constructor(private readonly prisma: PrismaService) {}

  async cleanupDeletedPatient(input: {
    patientId?: string | null;
    authUserId?: string | null;
  }) {
    const patientId = input.patientId?.trim() || null;
    const authUserId = input.authUserId?.trim() || null;
    if (!patientId && !authUserId) {
      return { affectedAccounts: 0 };
    }

    const accounts = await this.prisma.account.findMany({
      where: {
        OR: [
          ...(authUserId ? [{ id: authUserId }] : []),
          ...(patientId
            ? [
                {
                  roleProfiles: {
                    some: {
                      role: AccountRole.PATIENT,
                      subjectId: patientId,
                    },
                  },
                },
                {
                  productAccesses: {
                    some: {
                      product: ProductCode.PATIENT_PORTAL,
                      role: ProductRole.PATIENT,
                      subjectId: patientId,
                    },
                  },
                },
                {
                  role: AccountRole.PATIENT,
                  subjectId: patientId,
                },
              ]
            : []),
        ],
      },
      select: {
        id: true,
        email: true,
        role: true,
        subjectId: true,
      },
    });

    for (const account of accounts) {
      await this.prisma.$transaction(async (tx) => {
        await tx.accountRoleProfile.deleteMany({
          where: {
            accountId: account.id,
            role: AccountRole.PATIENT,
          },
        });
        await tx.accountProductAccess.deleteMany({
          where: {
            accountId: account.id,
            product: ProductCode.PATIENT_PORTAL,
            role: ProductRole.PATIENT,
          },
        });

        const data: {
          role?: AccountRole;
          subjectId?: string | null;
        } = {};
        if (account.role === AccountRole.PATIENT) {
          data.role = AccountRole.MEMBER;
        }
        if (account.role === AccountRole.PATIENT || (patientId && account.subjectId === patientId)) {
          data.subjectId = null;
        }
        if (Object.keys(data).length > 0) {
          await tx.account.update({
            where: { id: account.id },
            data,
          });
        }
      });
    }

    if (accounts.length > 0) {
      this.logger.log(
        `Limpieza de paciente aplicada para ${accounts.length} cuenta(s) patientId=${patientId ?? '-'} authUserId=${authUserId ?? '-'}`,
      );
    }

    return { affectedAccounts: accounts.length };
  }

  async cleanupDeletedDoctor(doctorIdRaw: string) {
    const doctorId = doctorIdRaw.trim();
    if (!doctorId) {
      return { affectedAccounts: 0 };
    }

    const accounts = await this.prisma.account.findMany({
      where: {
        OR: [
          { doctorId },
          {
            roleProfiles: {
              some: {
                role: AccountRole.DOCTOR,
                OR: [{ doctorId }, { subjectId: doctorId }],
              },
            },
          },
          {
            productAccesses: {
              some: {
                product: ProductCode.MEUDOC_PRO,
                subjectId: doctorId,
              },
            },
          },
        ],
      },
      select: {
        id: true,
        email: true,
        role: true,
        subjectId: true,
        doctorId: true,
      },
    });

    for (const account of accounts) {
      await this.prisma.$transaction(async (tx) => {
        await tx.accountRoleProfile.deleteMany({
          where: {
            accountId: account.id,
            role: AccountRole.DOCTOR,
          },
        });
        await tx.accountProductAccess.deleteMany({
          where: {
            accountId: account.id,
            product: ProductCode.MEUDOC_PRO,
            role: { in: this.doctorPortalRoles },
          },
        });

        const data: {
          role?: AccountRole;
          subjectId?: string | null;
          doctorId?: string | null;
        } = {};
        if (account.role === AccountRole.DOCTOR) {
          data.role = AccountRole.MEMBER;
        }
        if (account.role === AccountRole.DOCTOR || account.subjectId === doctorId) {
          data.subjectId = null;
        }
        if (account.role === AccountRole.DOCTOR || account.doctorId === doctorId) {
          data.doctorId = null;
        }
        if (Object.keys(data).length > 0) {
          await tx.account.update({
            where: { id: account.id },
            data,
          });
        }
      });
    }

    if (accounts.length > 0) {
      this.logger.log(
        `Limpieza de doctor aplicada para ${accounts.length} cuenta(s) doctorId=${doctorId}`,
      );
    }

    return { affectedAccounts: accounts.length };
  }
}
