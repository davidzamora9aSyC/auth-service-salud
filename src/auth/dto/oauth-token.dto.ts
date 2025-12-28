import { IsIn, IsOptional, IsString } from 'class-validator';

export class OAuthTokenDto {
  @IsString()
  @IsIn(['authorization_code', 'client_credentials'])
  grant_type!: string;

  @IsOptional()
  @IsString()
  code?: string;

  @IsOptional()
  @IsString()
  redirect_uri?: string;

  @IsString()
  client_id!: string;

  @IsOptional()
  @IsString()
  code_verifier?: string;

  @IsOptional()
  @IsString()
  client_secret?: string;

  @IsOptional()
  @IsString()
  scope?: string;
}
