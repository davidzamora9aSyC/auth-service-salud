import { IsEnum, IsOptional } from 'class-validator';
import { AccountDeletionChannel } from '@prisma/client';

export class AccountDeletionStartDto {
  @IsOptional()
  @IsEnum(AccountDeletionChannel)
  channel?: AccountDeletionChannel;
}
