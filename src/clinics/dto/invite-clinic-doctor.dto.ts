import { IsEmail, IsString } from 'class-validator';

export class InviteClinicDoctorDto {
  @IsEmail()
  doctorEmail!: string;
}
