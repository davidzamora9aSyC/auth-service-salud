import { BadRequestException, Injectable } from '@nestjs/common';
import { AccountRole, ProductCode, ProductRole } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';
import { ClinicDoctorIdentitiesDto } from './dto/clinic-doctor-identities.dto';

@Injectable()
export class ClinicDoctorIdentitiesService {
  constructor(private readonly prisma: PrismaService) {}

  async find(input: ClinicDoctorIdentitiesDto) {
    const email = input.email?.trim().toLowerCase();
    const doctorIds = input.doctorIds ?? [];
    if (Number(Boolean(email)) + Number(Boolean(input.accountId)) + Number(doctorIds.length > 0) !== 1) {
      throw new BadRequestException('Indica un solo criterio de busqueda');
    }
    const accounts = await this.prisma.account.findMany({
      where: email ? { email } : input.accountId ? { id: input.accountId } : {
        OR: [
          { roleProfiles: { some: { role: AccountRole.DOCTOR, OR: [{ doctorId: { in: doctorIds } }, { subjectId: { in: doctorIds } }] } } },
          { productAccesses: { some: { product: ProductCode.MEUDOC_PRO, role: ProductRole.DOCTOR, subjectId: { in: doctorIds } } } },
        ],
      },
      select: {
        id: true,
        email: true,
        roleProfiles: { where: { role: AccountRole.DOCTOR }, select: { doctorId: true, subjectId: true } },
        productAccesses: { where: { product: ProductCode.MEUDOC_PRO, role: ProductRole.DOCTOR }, select: { subjectId: true } },
      },
    });
    return accounts.map((account) => {
      const ids = Array.from(new Set([
        account.roleProfiles[0]?.doctorId,
        account.roleProfiles[0]?.subjectId,
        account.productAccesses[0]?.subjectId,
      ].filter((id): id is string => Boolean(id))));
      return { accountId: account.id, email: account.email, doctorId: ids[0] ?? null, inconsistent: ids.length > 1 };
    });
  }
}
