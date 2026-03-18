import { IsEnum, IsOptional } from 'class-validator';
import { AccountVerificationChannel } from '@prisma/client';

export class PhoneChangeStartDto {
  @IsOptional()
  @IsEnum(AccountVerificationChannel)
  channel?: AccountVerificationChannel;
}
