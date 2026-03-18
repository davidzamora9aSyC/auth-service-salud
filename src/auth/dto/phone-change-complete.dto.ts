import { IsNotEmpty, IsString, Matches } from 'class-validator';

export class PhoneChangeCompleteDto {
  @IsString()
  @IsNotEmpty()
  token!: string;

  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber!: string;
}
