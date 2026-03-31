import { Body, Controller, Get, Headers, Param, Post, UnauthorizedException } from '@nestjs/common';
import { AdminOnboardingService } from './admin-onboarding.service';
import { CreateDoctorOnboardingInviteDto } from './dto/create-doctor-onboarding-invite.dto';

@Controller()
export class AdminOnboardingController {
  constructor(private readonly onboarding: AdminOnboardingService) {}

  @Post('admin/doctor-onboarding/invites')
  createInvite(
    @Body() dto: CreateDoctorOnboardingInviteDto,
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.onboarding.createInvite(dto);
  }

  @Post('admin/doctor-onboarding/invites/:token/resend')
  resendInvite(
    @Param('token') token: string,
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.onboarding.resendInvite(token);
  }

  @Get('auth/doctor-onboarding/invites/:token')
  getInvite(@Param('token') token: string) {
    return this.onboarding.getInvitePrefill(token);
  }

  @Get('auth/doctor-onboarding/prefill-plan')
  getPreferredPlan(
    @Headers('x-role') role?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'DOCTOR' || !subjectId) {
      throw new UnauthorizedException('Token requerido');
    }
    return this.onboarding.getPreferredPlanByDoctor(subjectId);
  }
}
