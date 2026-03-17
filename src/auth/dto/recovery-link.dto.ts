import { IsString, MinLength } from 'class-validator';

export class RecoveryLinkDto {
  @IsString()
  @MinLength(16)
  token!: string;
}
