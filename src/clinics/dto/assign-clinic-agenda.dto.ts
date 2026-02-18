import { IsString } from 'class-validator';

export class AssignClinicAgendaDto {
  @IsString()
  agendaId!: string;

  @IsString()
  doctorId!: string;
}
