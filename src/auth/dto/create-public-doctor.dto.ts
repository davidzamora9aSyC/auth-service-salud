import { IsArray, IsObject, IsOptional, IsString } from 'class-validator';

export class CreatePublicDoctorDto {
  @IsString()
  firstName!: string;

  @IsString()
  lastName!: string;

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
}
