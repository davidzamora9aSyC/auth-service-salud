import { IsArray, IsEmail, IsObject, IsOptional, IsString, Matches } from 'class-validator';

export class CreateDoctorOnboardingInviteDto {
  @IsEmail()
  email!: string;

  @IsString()
  firstName!: string;

  @IsString()
  lastName!: string;

  @IsOptional()
  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber?: string;

  @IsOptional()
  @IsObject()
  profile?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  address?: Record<string, unknown>;

  @IsOptional()
  @IsObject()
  agenda?: Record<string, unknown>;

  @IsOptional()
  @IsArray()
  services?: Array<Record<string, unknown>>;

  @IsOptional()
  @IsString()
  planCode?: string;
}
