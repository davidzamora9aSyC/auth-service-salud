import { IsEnum, IsInt, IsOptional, IsString, IsUUID, Max, Min } from 'class-validator';
import { DoctorReferralStatus } from '@prisma/client';

export class ListDoctorReferralsDto {
  @IsOptional()
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;

  @IsOptional()
  @IsEnum(DoctorReferralStatus)
  status?: DoctorReferralStatus;

  @IsOptional()
  @IsString()
  q?: string;

  @IsOptional()
  @IsUUID()
  salesRepId?: string;
}
