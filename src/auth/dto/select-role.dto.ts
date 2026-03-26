import { IsEnum, IsString, MinLength } from 'class-validator';
import { AccountRole } from '@prisma/client';

export class SelectRoleDto {
  @IsString()
  @MinLength(10)
  refreshToken!: string;

  @IsEnum(AccountRole)
  role!: AccountRole;
}
