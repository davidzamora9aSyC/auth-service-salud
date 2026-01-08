import { CollaboratorStatus } from '@prisma/client';
import { IsArray, IsEnum, IsOptional, IsString } from 'class-validator';

export class UpdateCollaboratorDto {
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  permissions?: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  agendaIds?: string[];

  @IsOptional()
  @IsEnum(CollaboratorStatus)
  status?: CollaboratorStatus;
}
