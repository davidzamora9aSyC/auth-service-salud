import { IsEmail, IsIn, IsOptional, IsString } from 'class-validator';

export class AddClinicAdminDto {
  @IsEmail()
  email!: string;

  @IsOptional()
  @IsString()
  @IsIn(['OWNER', 'ADMIN'])
  role?: 'OWNER' | 'ADMIN';
}
