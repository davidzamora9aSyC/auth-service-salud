import { IsIn, IsOptional, IsString } from 'class-validator';

export class OAuthAuthorizeDto {
  @IsString()
  @IsIn(['code'])
  response_type!: string;

  @IsString()
  client_id!: string;

  @IsString()
  redirect_uri!: string;

  @IsString()
  code_challenge!: string;

  @IsString()
  @IsIn(['S256'])
  code_challenge_method!: string;

  @IsOptional()
  @IsString()
  scope?: string;

  @IsOptional()
  @IsString()
  state?: string;
}
