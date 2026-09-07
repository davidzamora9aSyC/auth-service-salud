import { ReferralType } from '@prisma/client';
import {
  IsEmail,
  IsEnum,
  IsOptional,
  IsString,
  Matches,
  MinLength,
  ValidateIf,
} from 'class-validator';

export class CreateReferralRegistrationInviteDto {
  @IsEnum(ReferralType)
  type!: ReferralType;

  @IsOptional()
  @IsString()
  referralId?: string;

  @IsString()
  @MinLength(1)
  firstName!: string;

  @IsString()
  @MinLength(1)
  lastName!: string;

  @IsEmail()
  email!: string;

  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber!: string;

  @ValidateIf((o: CreateReferralRegistrationInviteDto) => o.type === ReferralType.COMPANY)
  @IsString()
  @MinLength(2)
  companyName?: string;

  @ValidateIf((o: CreateReferralRegistrationInviteDto) => o.type === ReferralType.COMPANY)
  @IsString()
  @MinLength(5)
  taxId?: string;
}
