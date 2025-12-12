import { AccountRole } from '@prisma/client';
import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(8)
  password!: string;

  @IsEnum(AccountRole)
  role!: AccountRole;

  @IsOptional()
  @IsString()
  subjectId?: string;
}
