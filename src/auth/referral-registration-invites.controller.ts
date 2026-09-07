import { Body, Controller, Get, Headers, Param, Post } from '@nestjs/common';
import { CreateReferralRegistrationInviteDto } from './dto/create-referral-registration-invite.dto';
import { ReferralRegistrationInvitesService } from './referral-registration-invites.service';

@Controller()
export class ReferralRegistrationInvitesController {
  constructor(
    private readonly invites: ReferralRegistrationInvitesService,
  ) {}

  @Post('admin/referral-registration-invites')
  createInvite(
    @Body() dto: CreateReferralRegistrationInviteDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    return this.invites.createInvite(dto, {
      role: role?.trim(),
      authUserId: authUserId?.trim(),
    });
  }

  @Get('auth/referral-registration-invites/:token')
  getInvite(@Param('token') token: string) {
    return this.invites.getInviteByToken(token);
  }
}
