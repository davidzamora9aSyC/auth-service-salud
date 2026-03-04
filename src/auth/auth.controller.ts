import { Body, Controller, Delete, Get, Headers, Post, Query, Req, Res, UnauthorizedException } from '@nestjs/common';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterCollaboratorDto } from './dto/register-collaborator.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { TwoFactorSetupDto } from './dto/two-factor-setup.dto';
import { TwoFactorCodeDto } from './dto/two-factor-code.dto';
import { RecoveryStartDto } from './dto/recovery-start.dto';
import { RecoveryVerifyDto } from './dto/recovery-verify.dto';
import { RecoveryCompleteDto } from './dto/recovery-complete.dto';
import { BootstrapAdminDto } from './dto/bootstrap-admin.dto';
import { AccountDeletionStartDto } from './dto/account-deletion-start.dto';
import { AccountDeletionConfirmDto } from './dto/account-deletion-confirm.dto';
import { ImpersonateDoctorDto } from './dto/impersonate-doctor.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('register/collaborator')
  registerCollaborator(@Body() dto: RegisterCollaboratorDto) {
    return this.authService.registerCollaborator(dto);
  }

  @Post('admin/bootstrap')
  bootstrapAdmin(
    @Body() dto: BootstrapAdminDto,
    @Headers('x-admin-bootstrap-token') bootstrapToken?: string,
  ) {
    return this.authService.bootstrapAdmin(dto, bootstrapToken);
  }

  @Post('login')
  login(@Body() dto: LoginDto, @Req() req: Request) {
    return this.authService.login(dto, this.buildRequestMeta(req));
  }

  @Post('login/verify')
  verifyTwoFactor(@Body() dto: VerifyTwoFactorDto, @Req() req: Request) {
    return this.authService.verifyTwoFactor(dto, this.buildRequestMeta(req));
  }

  @Post('refresh')
  refresh(@Body() dto: RefreshTokenDto) {
    return this.authService.refresh(dto.refreshToken);
  }

  @Post('logout')
  logout(@Body() dto: RefreshTokenDto) {
    return this.authService.logout(dto.refreshToken);
  }

  @Get('login-history')
  getLoginHistory(
    @Query('limit') limit: string | undefined,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    const parsedLimit = Number.parseInt(limit ?? '', 10);
    const safeLimit = Number.isFinite(parsedLimit) ? Math.min(Math.max(parsedLimit, 1), 50) : 20;
    return this.authService.getLoginHistory(authUserId, safeLimit);
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

  @Post('account-deletion/start')
  startAccountDeletion(
    @Body() dto: AccountDeletionStartDto,
    @Req() req: Request,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.startAccountDeletion(
      authUserId,
      dto,
      this.buildRequestMeta(req),
    );
  }

  @Post('account-deletion/confirm')
  confirmAccountDeletion(
    @Body() dto: AccountDeletionConfirmDto,
    @Req() req: Request,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.confirmAccountDeletion(
      authUserId,
      dto,
      this.buildRequestMeta(req),
    );
  }

  @Post('internal/impersonate/doctor')
  impersonateDoctor(
    @Body() dto: ImpersonateDoctorDto,
    @Headers('x-api-key') apiKey?: string,
  ) {
    const expected = process.env.AUTH_INTERNAL_API_KEY;
    if (expected && apiKey !== expected) {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.impersonateDoctor(dto.doctorId);
  }

  @Get('oauth/google')
  startGoogleOAuth(@Query('role') role: string, @Query('redirect') redirect: string | undefined, @Res() res: Response) {
    const url = this.authService.getGoogleOAuthUrl(role, redirect);
    return res.redirect(url);
  }

  @Get('oauth/google/callback')
  async handleGoogleCallback(@Query('code') code: string, @Query('state') state: string, @Req() req: Request, @Res() res: Response) {
    const result = await this.authService.handleGoogleOAuthCallback(code, state, this.buildRequestMeta(req));
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
  async handleAppleCallbackGet(@Query('code') code: string, @Query('state') state: string, @Req() req: Request, @Res() res: Response) {
    const result = await this.authService.handleAppleOAuthCallback(code, state, this.buildRequestMeta(req));
    if (result.redirect) {
      return res.redirect(result.redirect);
    }
    return res.json(result.payload);
  }

  @Post('oauth/apple/callback')
  async handleAppleCallbackPost(@Body('code') code: string, @Body('state') state: string, @Req() req: Request, @Res() res: Response) {
    const result = await this.authService.handleAppleOAuthCallback(code, state, this.buildRequestMeta(req));
    if (result.redirect) {
      return res.redirect(result.redirect);
    }
    return res.json(result.payload);
  }

  private buildRequestMeta(req: Request) {
    return {
      ip: req.ip ?? undefined,
      forwardedFor:
        typeof req.headers['x-forwarded-for'] === 'string'
          ? req.headers['x-forwarded-for']
          : Array.isArray(req.headers['x-forwarded-for'])
            ? req.headers['x-forwarded-for'][0]
            : undefined,
      userAgent:
        typeof req.headers['user-agent'] === 'string'
          ? req.headers['user-agent']
          : undefined,
    };
  }
}
