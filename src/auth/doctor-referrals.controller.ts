import {
  Body,
  Controller,
  Get,
  Headers,
  Param,
  Patch,
  Post,
  Query,
  UnauthorizedException,
} from '@nestjs/common';
import { DoctorReferralsService } from './doctor-referrals.service';
import { CreateDoctorReferralDto } from './dto/create-doctor-referral.dto';
import { ListDoctorReferralsDto } from './dto/list-doctor-referrals.dto';
import { UpdateDoctorReferralDto } from './dto/update-doctor-referral.dto';

const assertAdminRole = (role?: string) => {
  const normalizedRole = role?.toUpperCase();
  if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
    throw new UnauthorizedException('No autorizado');
  }
};

const assertCommercialRole = (role?: string, authUserId?: string) => {
  const normalizedRole = role?.toUpperCase();
  if (normalizedRole !== 'COMERCIAL' || !authUserId) {
    throw new UnauthorizedException('No autorizado');
  }
};

@Controller()
export class DoctorReferralsController {
  constructor(private readonly referrals: DoctorReferralsService) {}

  @Post('comercial/referrals')
  createForCommercial(
    @Body() dto: CreateDoctorReferralDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertCommercialRole(role, authUserId);
    return this.referrals.createReferral(
      { role: 'COMERCIAL', authUserId: authUserId! },
      dto,
    );
  }

  @Get('comercial/referrals')
  listForCommercial(
    @Query() query: ListDoctorReferralsDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertCommercialRole(role, authUserId);
    return this.referrals.listReferralsForCommercial(authUserId!, query);
  }

  @Get('comercial/referrals/:id')
  getForCommercial(
    @Param('id') id: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertCommercialRole(role, authUserId);
    return this.referrals.getReferralForCommercial(authUserId!, id);
  }

  @Patch('comercial/referrals/:id')
  updateForCommercial(
    @Param('id') id: string,
    @Body() dto: UpdateDoctorReferralDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertCommercialRole(role, authUserId);
    return this.referrals.updateReferralForCommercial(authUserId!, id, dto);
  }

  @Get('comercial/referrals/:id/metrics')
  metricsForCommercial(
    @Param('id') id: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertCommercialRole(role, authUserId);
    return this.referrals.getReferralMetricsForCommercial(authUserId!, id);
  }

  @Get('comercial/referrals/:id/payments-report')
  paymentsReportForCommercial(
    @Param('id') id: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    assertCommercialRole(role, authUserId);
    return this.referrals.getReferralPaymentsReportForCommercial(authUserId!, id);
  }

  @Get('admin/referrals')
  listForAdmin(@Query() query: ListDoctorReferralsDto, @Headers('x-role') role?: string) {
    assertAdminRole(role);
    return this.referrals.listReferralsForAdmin(query);
  }

  @Get('admin/referrals/:id/metrics')
  metricsForAdmin(@Param('id') id: string, @Headers('x-role') role?: string) {
    assertAdminRole(role);
    return this.referrals.getReferralMetricsForAdmin(id);
  }

  @Get('admin/referrals/:id/payments-report')
  paymentsReportForAdmin(@Param('id') id: string, @Headers('x-role') role?: string) {
    assertAdminRole(role);
    return this.referrals.getReferralPaymentsReportForAdmin(id);
  }

  @Get('admin/referrals/:id')
  getForAdmin(@Param('id') id: string, @Headers('x-role') role?: string) {
    assertAdminRole(role);
    return this.referrals.getReferralForAdmin(id);
  }

  @Patch('admin/referrals/:id')
  updateForAdmin(
    @Param('id') id: string,
    @Body() dto: UpdateDoctorReferralDto,
    @Headers('x-role') role?: string,
  ) {
    assertAdminRole(role);
    return this.referrals.updateReferralForAdmin(id, dto);
  }
}
