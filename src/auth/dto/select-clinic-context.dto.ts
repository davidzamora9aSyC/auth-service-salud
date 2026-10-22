import { IsString, MinLength } from 'class-validator';

export class SelectClinicContextDto {
  @IsString()
  @MinLength(10)
  refreshToken!: string;

  @IsString()
  @MinLength(1)
  membershipId!: string;
}
