import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class PhoneChangeVerifyDto {
  @IsString()
  @IsNotEmpty()
  changeId!: string;

  @IsString()
  @Matches(/^\d{6}$/, { message: 'code must be 6 digits' })
  code!: string;
}
