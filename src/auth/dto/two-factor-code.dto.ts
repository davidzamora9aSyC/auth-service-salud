import { IsOptional, IsString, Length } from 'class-validator';

export class TwoFactorCodeDto {
  @IsString()
  @Length(3, 10)
  code!: string;

  @IsOptional()
  @IsString()
  @Length(32, 64)
  challengeId?: string;
}
