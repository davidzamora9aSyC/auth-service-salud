import { IsEmail, IsOptional, IsString, MinLength } from 'class-validator';

export class RegisterCollaboratorDto {
  @IsEmail()
  email!: string;

  @IsOptional()
  @IsString()
  phoneNumber?: string;

  @IsString()
  @MinLength(8)
  password!: string;

  @IsString()
  firstName!: string;

  @IsString()
  lastName!: string;

  @IsString()
  inviteToken!: string;
}
