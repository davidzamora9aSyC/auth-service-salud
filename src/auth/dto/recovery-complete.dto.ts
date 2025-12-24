import { IsNotEmpty, IsString, MinLength } from 'class-validator';

export class RecoveryCompleteDto {
  @IsString()
  @IsNotEmpty()
  resetToken!: string;

  @IsString()
  @MinLength(10)
  password!: string;
}
