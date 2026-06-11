import { IsEnum, IsUUID } from 'class-validator';
import { ProductRole } from '@prisma/client';

const employerAccessRoles = [ProductRole.EMPLOYER_ADMIN, ProductRole.EMPLOYER_BILLING] as const;

export class GrantEmployerAccessDto {
  @IsUUID()
  accountId!: string;

  @IsUUID()
  employerId!: string;

  @IsEnum(employerAccessRoles)
  productRole!: (typeof employerAccessRoles)[number];
}
