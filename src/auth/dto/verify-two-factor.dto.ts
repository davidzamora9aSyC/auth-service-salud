import { IsString, Length } from 'class-validator';

export class VerifyTwoFactorDto {
  @IsString()
  @Length(32, 64)
  challengeId!: string;

  @IsString()
  @Length(3, 10)
  code!: string;
}
