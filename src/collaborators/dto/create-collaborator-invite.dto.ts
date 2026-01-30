import { IsArray, IsEmail, IsInt, IsOptional, IsString, IsUUID, Min } from 'class-validator';

export class CreateCollaboratorInviteDto {
  @IsOptional()
  @IsUUID()
  doctorId?: string;

  @IsEmail()
  email!: string;

  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @IsArray()
  @IsString({ each: true })
  permissions!: string[];

  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  agendaIds?: string[];

  @IsOptional()
  @IsString()
  inviterAccountId?: string;

  @IsOptional()
  @IsInt()
  @Min(15)
  expiresInMinutes?: number;
}
