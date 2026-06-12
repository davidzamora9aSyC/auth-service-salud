import { IsEmail, IsEnum, IsOptional, IsString, Matches, MaxLength } from 'class-validator';
import { DoctorReferralStatus } from '@prisma/client';

export class CreateDoctorReferralDto {
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

  @IsOptional()
  @IsEnum(DoctorReferralStatus)
  status?: DoctorReferralStatus;

  @IsOptional()
  @IsString()
  @MaxLength(500)
  statusNote?: string;
}
