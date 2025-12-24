import { IsNotEmpty, IsString, Length } from 'class-validator';

export class RecoveryVerifyDto {
  @IsString()
  @IsNotEmpty()
  recoveryId!: string;

  @IsString()
  @Length(6, 6)
  code!: string;
}
