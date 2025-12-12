import { TwoFactorMethod } from '@prisma/client';
import { IsEnum, IsOptional, IsString, MinLength } from 'class-validator';

export class TwoFactorSetupDto {
  @IsString()
  @MinLength(10)
  refreshToken!: string;

  @IsOptional()
  @IsEnum(TwoFactorMethod)
  method?: TwoFactorMethod;
}
