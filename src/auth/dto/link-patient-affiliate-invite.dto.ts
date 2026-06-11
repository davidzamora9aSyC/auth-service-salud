import { IsEmail, IsOptional, IsString, Matches, MinLength } from 'class-validator';

export class LinkPatientAffiliateInviteDto {
  @IsEmail()
  email!: string;

  @IsString()
  @MinLength(1)
  firstName!: string;

  @IsString()
  @MinLength(1)
  lastName!: string;

  @IsOptional()
  @IsString()
  @Matches(/^\+?[1-9]\d{7,14}$/, {
    message: 'phoneNumber must include the country code (E.164)',
  })
  phoneNumber?: string;
}
