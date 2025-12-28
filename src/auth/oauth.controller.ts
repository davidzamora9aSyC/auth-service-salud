import { Body, Controller, Get, Headers, Post, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { OAuthAuthorizeDto } from './dto/oauth-authorize.dto';
import { OAuthTokenDto } from './dto/oauth-token.dto';

@Controller('oauth')
export class OAuthController {
  constructor(private readonly authService: AuthService) {}

  @Get('authorize')
  async authorize(
    @Query() dto: OAuthAuthorizeDto,
    @Headers('authorization') authorization: string | undefined,
    @Res() res: Response,
  ) {
    const redirectUrl = await this.authService.authorizeOAuth(dto, authorization);
    return res.redirect(redirectUrl);
  }

  @Post('token')
  token(@Body() dto: OAuthTokenDto) {
    return this.authService.exchangeOAuthToken(dto);
  }
}
