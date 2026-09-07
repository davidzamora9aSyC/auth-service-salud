import { IsEmail, IsEnum, IsOptional, IsString, Matches, MaxLength, MinLength, ValidateIf } from 'class-validator';
import { DoctorReferralStatus, ReferralType } from '@prisma/client';

export class CreateDoctorReferralDto {
  @IsOptional()
  @IsEnum(ReferralType)
  referralType?: ReferralType;

  @IsString()
  @MaxLength(160)
  fullName!: string;

  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber!: string;

  @IsOptional()
  @IsEmail()
  email?: string;

  @ValidateIf((o: CreateDoctorReferralDto) => (o.referralType ?? ReferralType.DOCTOR) === ReferralType.COMPANY)
  @IsString()
  @MinLength(2)
  @MaxLength(160)
  companyName?: string;

  @ValidateIf((o: CreateDoctorReferralDto) => (o.referralType ?? ReferralType.DOCTOR) === ReferralType.COMPANY)
  @IsString()
  @MinLength(5)
  @MaxLength(80)
  taxId?: string;

  @IsOptional()
  @IsEnum(DoctorReferralStatus)
  status?: DoctorReferralStatus;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  statusNote?: string;
}
