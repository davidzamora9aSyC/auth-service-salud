import { IsNotEmpty, IsString, Length } from 'class-validator';

export class AccountDeletionConfirmDto {
  @IsString()
  @IsNotEmpty()
  challengeId!: string;

  @IsString()
  @Length(6, 6)
  code!: string;
}
