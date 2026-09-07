import { IsEmail, IsEnum, IsOptional, IsString, Matches, MaxLength, MinLength, ValidateIf } from 'class-validator';
import { DoctorReferralStatus, ReferralType } from '@prisma/client';

export class UpdateDoctorReferralDto {
  @IsOptional()
  @IsEnum(ReferralType)
  referralType?: ReferralType;

  @IsOptional()
  @IsString()
  @MaxLength(160)
  fullName?: string;

  @IsOptional()
  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber?: string;

  @IsOptional()
  @IsEmail()
  email?: string | null;

  @ValidateIf((o: UpdateDoctorReferralDto) => o.referralType === ReferralType.COMPANY || o.companyName !== undefined)
  @IsString()
  @MinLength(2)
  @MaxLength(160)
  companyName?: string | null;

  @ValidateIf((o: UpdateDoctorReferralDto) => o.referralType === ReferralType.COMPANY || o.taxId !== undefined)
  @IsString()
  @MinLength(5)
  @MaxLength(80)
  taxId?: string | null;

  @IsOptional()
  @IsEnum(DoctorReferralStatus)
  status?: DoctorReferralStatus;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  statusNote?: string | null;

  @IsOptional()
  @IsString()
  salesRepId?: string;
}
