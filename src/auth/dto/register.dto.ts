import { AccountRole } from '@prisma/client';
import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  Matches,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class RegisterDto {
  @IsEmail()
  email!: string;

  @IsOptional()
  @IsString()
  firstName?: string;

  @IsOptional()
  @IsString()
  lastName?: string;

  @IsString()
  @MinLength(8)
  password!: string;

  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber!: string;

  @IsEnum(AccountRole)
  role!: AccountRole;

  @IsOptional()
  @IsString()
  subjectId?: string;

  @IsOptional()
  @IsString()
  inviteToken?: string;

  @ValidateIf(
    (o: { role?: AccountRole; inviteToken?: string }) =>
      o.role === AccountRole.EMPLOYER && !o.inviteToken?.trim(),
  )
  @IsString()
  @MinLength(2, { message: 'companyName is required for employer registration' })
  companyName?: string;

  @ValidateIf(
    (o: { role?: AccountRole; inviteToken?: string }) =>
      o.role === AccountRole.EMPLOYER && !o.inviteToken?.trim(),
  )
  @IsString()
  @MinLength(5, { message: 'taxId is required for employer registration' })
  taxId?: string;
}
