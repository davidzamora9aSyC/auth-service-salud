import { AccountRole } from '@prisma/client';
import { IsEmail, IsEnum, IsOptional, IsString, MaxLength } from 'class-validator';

export class SimulateUserRegisteredDto {
  @IsEnum(AccountRole)
  role!: AccountRole;

  @IsEmail()
  @MaxLength(320)
  email!: string;

  @IsOptional()
  @IsString()
  @MaxLength(32)
  phoneNumber?: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  firstName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(120)
  lastName?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  authUserId?: string;

  @IsOptional()
  @IsString()
  @MaxLength(64)
  doctorId?: string;
}
