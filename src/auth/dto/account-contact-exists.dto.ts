import { IsEmail, IsOptional, Matches } from 'class-validator';

export class AccountContactExistsDto {
  @IsOptional()
  @IsEmail()
  email?: string;

  @IsOptional()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber?: string;
}
