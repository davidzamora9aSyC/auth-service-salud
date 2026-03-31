import { IsEmail } from 'class-validator';

export class AdminDeleteAccountDto {
  @IsEmail()
  confirmEmail!: string;
}
