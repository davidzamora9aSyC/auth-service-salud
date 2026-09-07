import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AdminOnboardingController } from './admin-onboarding.controller';
import { AdminAccountsController } from './admin-accounts.controller';
import { AdminCompaniesController } from './admin-companies.controller';
import { AdminCommercialAccountsController } from './admin-commercial-accounts.controller';
import { DoctorReferralsController } from './doctor-referrals.controller';
import { ReferralRegistrationInvitesController } from './referral-registration-invites.controller';
import { OAuthController } from './oauth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { RabbitmqService } from './rabbitmq.service';
import { DoctorsConsumer } from './doctors.consumer';
import { PatientsConsumer } from './patients.consumer';
import { ClinicsConsumer } from './clinics.consumer';
import { EmployersConsumer } from './employers.consumer';
import { EmployerMemberActivatedConsumer } from './employer-member-activated.consumer';
import { AdminOnboardingService } from './admin-onboarding.service';
import { DoctorReferralsService } from './doctor-referrals.service';
import { ReferralRegistrationInvitesService } from './referral-registration-invites.service';
import { ReferralsConsumer } from './referrals.consumer';
import { EmployersHttpClient } from './employers-http.client';
import { RegistrationPrefillService } from './registration-prefill.service';
import { AccountLinkCleanupService } from './account-link-cleanup.service';

@Module({
  imports: [PrismaModule, NotificationsModule],
  controllers: [
    AuthController,
    OAuthController,
    AdminOnboardingController,
    AdminAccountsController,
    AdminCompaniesController,
    AdminCommercialAccountsController,
    DoctorReferralsController,
    ReferralRegistrationInvitesController,
  ],
  providers: [
    AuthService,
    RabbitmqService,
    AccountLinkCleanupService,
    DoctorsConsumer,
    PatientsConsumer,
    ReferralsConsumer,
    ClinicsConsumer,
    EmployersConsumer,
    EmployerMemberActivatedConsumer,
    AdminOnboardingService,
    DoctorReferralsService,
    ReferralRegistrationInvitesService,
    EmployersHttpClient,
    RegistrationPrefillService,
  ],
})
export class AuthModule {}
