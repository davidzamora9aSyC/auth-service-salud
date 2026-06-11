import { IsEmail } from 'class-validator';

export class EmailExistsDto {
  @IsEmail()
  email!: string;
}
