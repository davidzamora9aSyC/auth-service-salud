import { IsString, Length, MinLength } from 'class-validator';

export class TwoFactorCodeDto {
  @IsString()
  @MinLength(10)
  refreshToken!: string;

  @IsString()
  @Length(3, 10)
  code!: string;
}
