import { Body, Controller, Get, Headers, Param, Post, Query, UnauthorizedException } from '@nestjs/common';
import { AdminOnboardingService } from './admin-onboarding.service';
import { CreateDoctorOnboardingInviteDto } from './dto/create-doctor-onboarding-invite.dto';
import { CreatePublicDoctorDto } from './dto/create-public-doctor.dto';
import { AdminListDoctorOnboardingInvitesDto } from './dto/admin-list-doctor-onboarding-invites.dto';
import { UpdateDoctorOnboardingSettingsDto } from './dto/update-doctor-onboarding-settings.dto';

const assertStaffRole = (role?: string) => {
  const normalizedRole = role?.toUpperCase();
  if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM' && normalizedRole !== 'COMERCIAL') {
    throw new UnauthorizedException('No autorizado');
  }
  return normalizedRole!;
};

const assertAdminRole = (role?: string) => {
  const normalizedRole = role?.toUpperCase();
  if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
    throw new UnauthorizedException('No autorizado');
  }
  return normalizedRole!;
};

@Controller()
export class AdminOnboardingController {
  constructor(private readonly onboarding: AdminOnboardingService) {}

  @Get('admin/doctor-onboarding/invites')
  listInvites(
    @Query() query: AdminListDoctorOnboardingInvitesDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertStaffRole(role);
    return this.onboarding.listInvites(query, { role: role!.toUpperCase(), authUserId });
  }

  @Get('admin/doctor-onboarding/settings')
  getSettings(@Headers('x-role') role?: string) {
    assertStaffRole(role);
    return this.onboarding.getSettings();
  }

  @Post('admin/doctor-onboarding/settings')
  updateSettings(
    @Body() dto: UpdateDoctorOnboardingSettingsDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertAdminRole(role);
    return this.onboarding.updateSettings(dto, authUserId);
  }

  @Post('admin/doctor-onboarding/invites')
  createInvite(
    @Body() dto: CreateDoctorOnboardingInviteDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertStaffRole(role);
    return this.onboarding.createInvite(dto, { role: role!.toUpperCase(), authUserId });
  }

  @Post('admin/doctor-onboarding/prefill-only')
  createPublicDoctor(
    @Body() dto: CreatePublicDoctorDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertStaffRole(role);
    return this.onboarding.createPublicDoctor(dto, { role: role!.toUpperCase(), authUserId });
  }

  @Post('admin/doctor-onboarding/invites/:token/resend')
  resendInvite(
    @Param('token') token: string,
    @Headers('x-role') role?: string,
  ) {
    assertStaffRole(role);
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

  @Get('internal/doctor-onboarding/doctors/:doctorId/prefill-plan')
  getInternalPreferredPlan(
    @Param('doctorId') doctorId: string,
    @Headers('x-api-key') apiKey?: string,
  ) {
    const expected = process.env.AUTH_INTERNAL_API_KEY;
    if (expected && apiKey !== expected) {
      throw new UnauthorizedException('No autorizado');
    }
    return this.onboarding.getPreferredPlanByDoctor(doctorId);
  }
}
