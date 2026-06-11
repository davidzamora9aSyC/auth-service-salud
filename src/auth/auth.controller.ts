import { Body, Controller, Delete, Get, Headers, Post, Query, Req, Res, UnauthorizedException } from '@nestjs/common';
import { SelectRoleDto } from './dto/select-role.dto';
import { Request, Response } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterCollaboratorDto } from './dto/register-collaborator.dto';
import { CreateEmployerInviteAccountDto } from './dto/create-employer-invite-account.dto';
import { CreatePatientInviteAccountDto } from './dto/create-patient-invite-account.dto';
import { EmailExistsDto } from './dto/email-exists.dto';
import { LinkPatientAffiliateInviteDto } from './dto/link-patient-affiliate-invite.dto';
import { GrantEmployerAccessDto } from './dto/grant-employer-access.dto';
import { VerifyTwoFactorDto } from './dto/verify-two-factor.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { TwoFactorSetupDto } from './dto/two-factor-setup.dto';
import { TwoFactorCodeDto } from './dto/two-factor-code.dto';
import { RecoveryStartDto } from './dto/recovery-start.dto';
import { RecoveryVerifyDto } from './dto/recovery-verify.dto';
import { RecoveryCompleteDto } from './dto/recovery-complete.dto';
import { RecoveryLinkDto } from './dto/recovery-link.dto';
import { PhoneAvailabilityDto } from './dto/phone-availability.dto';
import { BootstrapAdminDto } from './dto/bootstrap-admin.dto';
import { AccountDeletionStartDto } from './dto/account-deletion-start.dto';
import { AccountDeletionConfirmDto } from './dto/account-deletion-confirm.dto';
import { ImpersonateDoctorDto } from './dto/impersonate-doctor.dto';
import { PasswordChangeStartDto } from './dto/password-change-start.dto';
import { PhoneChangeStartDto } from './dto/phone-change-start.dto';
import { PhoneChangeVerifyDto } from './dto/phone-change-verify.dto';
import { PhoneChangeCompleteDto } from './dto/phone-change-complete.dto';
import { RegisterMeuredDto } from './dto/register-meured.dto';
import { SelectProductAccessDto } from './dto/select-product-access.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('register/meured')
  registerMeured(@Body() dto: RegisterMeuredDto) {
    return this.authService.registerMeured(dto);
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

  @Post('select-role')
  selectRole(@Body() dto: SelectRoleDto) {
    return this.authService.selectRole(dto.refreshToken, dto.role);
  }

  @Get('product-access/me')
  productAccessMe(@Headers('x-auth-user-id') authUserId?: string) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.listProductAccess(authUserId);
  }

  @Post('product-access/select')
  selectProductAccess(@Body() dto: SelectProductAccessDto) {
    return this.authService.selectProductAccess(dto);
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

  @Get('2fa')
  getTwoFactorStatus(@Headers('x-auth-user-id') authUserId?: string) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.getTwoFactorStatus(authUserId);
  }

  @Post('2fa/setup')
  setupTwoFactor(
    @Body() dto: TwoFactorSetupDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.setupTwoFactor(authUserId, dto);
  }

  @Post('2fa/activate')
  activateTwoFactor(
    @Body() dto: TwoFactorCodeDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.confirmTwoFactor(authUserId, dto);
  }

  @Post('2fa/disable/start')
  startDisableTwoFactor(@Headers('x-auth-user-id') authUserId?: string) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.startDisableTwoFactor(authUserId);
  }

  @Delete('2fa')
  disableTwoFactor(
    @Body() dto: TwoFactorCodeDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.disableTwoFactor(authUserId, dto);
  }

  @Post('recovery/start')
  startRecovery(@Body() dto: RecoveryStartDto) {
    return this.authService.startPasswordRecovery(dto);
  }

  @Post('recovery/start/me')
  startRecoveryForAccount(
    @Body() dto: PasswordChangeStartDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.startPasswordRecoveryForAccount(authUserId, dto);
  }

  @Post('recovery/verify')
  verifyRecovery(@Body() dto: RecoveryVerifyDto) {
    return this.authService.verifyPasswordRecovery(dto);
  }

  @Post('recovery/magic')
  verifyRecoveryLink(@Body() dto: RecoveryLinkDto) {
    return this.authService.verifyPasswordRecoveryLink(dto);
  }

  @Post('recovery/complete')
  completeRecovery(@Body() dto: RecoveryCompleteDto) {
    return this.authService.completePasswordRecovery(dto);
  }

  @Post('account/phone-change/start')
  startPhoneChange(
    @Body() dto: PhoneChangeStartDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.startPhoneChange(authUserId, dto);
  }

  @Post('account/phone-change/verify')
  verifyPhoneChange(
    @Body() dto: PhoneChangeVerifyDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.verifyPhoneChange(authUserId, dto);
  }

  @Post('account/phone-change/complete')
  completePhoneChange(
    @Body() dto: PhoneChangeCompleteDto,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    if (!authUserId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.authService.completePhoneChange(authUserId, dto);
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

  @Post('internal/phone/availability')
  checkPhoneAvailability(
    @Body() dto: PhoneAvailabilityDto,
    @Headers('x-api-key') apiKey?: string,
  ) {
    const expected = process.env.AUTH_INTERNAL_API_KEY;
    if (expected && apiKey !== expected) {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.checkPhoneAvailability(dto);
  }

  @Post('internal/employer-invite/accounts')
  createEmployerInviteAccount(
    @Body() dto: CreateEmployerInviteAccountDto,
    @Headers('x-internal-service-token') internalToken?: string,
  ) {
    this.assertInternalServiceToken(internalToken);
    return this.authService.createEmployerInviteAccount(dto);
  }

  @Post('internal/employer-member/verify-or-create')
  verifyOrCreateEmployerMember(
    @Body() dto: CreateEmployerInviteAccountDto,
    @Headers('x-internal-service-token') internalToken?: string,
  ) {
    this.assertInternalServiceToken(internalToken);
    return this.authService.verifyOrCreateEmployerMemberForInvite(dto);
  }

  @Post('internal/patient/verify-or-create')
  verifyOrCreatePatient(
    @Body() dto: CreatePatientInviteAccountDto,
    @Headers('x-internal-service-token') internalToken?: string,
  ) {
    this.assertInternalServiceToken(internalToken);
    return this.authService.verifyOrCreatePatientForInvite(dto);
  }

  @Post('internal/accounts/email-exists')
  emailExists(
    @Body() dto: EmailExistsDto,
    @Headers('x-internal-service-token') internalToken?: string,
  ) {
    this.assertInternalServiceToken(internalToken);
    return this.authService.accountExistsByEmail(dto.email);
  }

  @Post('internal/patient/link-affiliate-invite')
  linkPatientAffiliateInvite(
    @Body() dto: LinkPatientAffiliateInviteDto,
    @Headers('x-internal-service-token') internalToken?: string,
  ) {
    this.assertInternalServiceToken(internalToken);
    return this.authService.linkPatientForAffiliateInvite(dto);
  }

  @Post('internal/employer-access/grant')
  grantEmployerAccess(
    @Body() dto: GrantEmployerAccessDto,
    @Headers('x-internal-service-token') internalToken?: string,
  ) {
    this.assertInternalServiceToken(internalToken);
    return this.authService.grantEmployerAccess(dto);
  }

  private assertInternalServiceToken(token?: string) {
    const expected = process.env.INTERNAL_SERVICE_TOKEN;
    if (expected && token !== expected) {
      throw new UnauthorizedException('No autorizado');
    }
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
