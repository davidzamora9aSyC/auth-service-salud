import { ArrayMaxSize, IsArray, IsEmail, IsOptional, IsUUID } from 'class-validator';

export class ClinicDoctorIdentitiesDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @IsUUID()
  accountId?: string;

  @IsOptional()
  @IsArray()
  @ArrayMaxSize(500)
  @IsUUID('all', { each: true })
  doctorIds?: string[];
}
