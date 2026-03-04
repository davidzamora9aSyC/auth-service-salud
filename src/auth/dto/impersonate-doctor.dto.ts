import { IsUUID } from 'class-validator';

export class ImpersonateDoctorDto {
  @IsUUID()
  doctorId: string;
}
