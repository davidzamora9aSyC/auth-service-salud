import { Body, Controller, Delete, Get, Post, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { TwoFactorSetupDto } from './dto/two-factor-setup.dto';
import { TwoFactorCodeDto } from './dto/two-factor-code.dto';
import { RecoveryStartDto } from './dto/recovery-start.dto';
import { RecoveryVerifyDto } from './dto/recovery-verify.dto';
import { RecoveryCompleteDto } from './dto/recovery-complete.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('login/verify')
  verifyTwoFactor(@Body() dto: VerifyTwoFactorDto) {
    return this.authService.verifyTwoFactor(dto);
  }

  @Post('refresh')
  refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  logout(@Body() dto: RefreshTokenDto) {
    return this.authService.logout(dto.refreshToken);
  }

  @Post('2fa/setup')
  setupTwoFactor(@Body() dto: TwoFactorSetupDto) {
    return this.authService.setupTwoFactor(dto);
  }

  @Post('2fa/activate')
  activateTwoFactor(@Body() dto: TwoFactorCodeDto) {
    return this.authService.confirmTwoFactor(dto);
  }

  @Delete('2fa')
  disableTwoFactor(@Body() dto: TwoFactorCodeDto) {
    return this.authService.disableTwoFactor(dto);
  }

  @Post('recovery/start')
  startRecovery(@Body() dto: RecoveryStartDto) {
    return this.authService.startPasswordRecovery(dto);
  }

  @Post('recovery/verify')
  verifyRecovery(@Body() dto: RecoveryVerifyDto) {
    return this.authService.verifyPasswordRecovery(dto);
  }

  @Post('recovery/complete')
  completeRecovery(@Body() dto: RecoveryCompleteDto) {
    return this.authService.completePasswordRecovery(dto);
  }

  @Get('oauth/google')
  startGoogleOAuth(@Query('role') role: string, @Query('redirect') redirect: string | undefined, @Res() res: Response) {
    const url = this.authService.getGoogleOAuthUrl(role, redirect);
    return res.redirect(url);
  }

  @Get('oauth/google/callback')
  async handleGoogleCallback(@Query('code') code: string, @Query('state') state: string, @Res() res: Response) {
    const result = await this.authService.handleGoogleOAuthCallback(code, state);
    if (result.redirect) {
      return res.redirect(result.redirect);
    }
    return res.json(result.payload);
  }

  @Get('oauth/apple')
  startAppleOAuth(@Query('role') role: string, @Query('redirect') redirect: string | undefined, @Res() res: Response) {
    const url = this.authService.getAppleOAuthUrl(role, redirect);
    return res.redirect(url);
  }

  @Get('oauth/apple/callback')
  async handleAppleCallbackGet(@Query('code') code: string, @Query('state') state: string, @Res() res: Response) {
    const result = await this.authService.handleAppleOAuthCallback(code, state);
    if (result.redirect) {
      return res.redirect(result.redirect);
    }
    return res.json(result.payload);
  }

  @Post('oauth/apple/callback')
  async handleAppleCallbackPost(@Body('code') code: string, @Body('state') state: string, @Res() res: Response) {
    const result = await this.authService.handleAppleOAuthCallback(code, state);
    if (result.redirect) {
      return res.redirect(result.redirect);
    }
    return res.json(result.payload);
  }
}
