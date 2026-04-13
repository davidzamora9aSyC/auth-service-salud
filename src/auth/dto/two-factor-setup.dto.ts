import { TwoFactorMethod } from '@prisma/client';
import { IsEnum } from 'class-validator';

export class TwoFactorSetupDto {
  @IsEnum(TwoFactorMethod)
  method!: TwoFactorMethod;
}
