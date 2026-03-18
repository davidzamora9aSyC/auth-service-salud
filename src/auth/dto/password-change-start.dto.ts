import { IsEnum, IsOptional } from 'class-validator';
import { AccountDeletionChannel } from '@prisma/client';

export class PasswordChangeStartDto {
  @IsOptional()
  @IsEnum(AccountDeletionChannel)
  channel?: AccountDeletionChannel;
}
