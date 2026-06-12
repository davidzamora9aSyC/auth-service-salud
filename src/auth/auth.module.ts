import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AdminOnboardingController } from './admin-onboarding.controller';
import { AdminAccountsController } from './admin-accounts.controller';
import { AdminCommercialAccountsController } from './admin-commercial-accounts.controller';
import { DoctorReferralsController } from './doctor-referrals.controller';
import { OAuthController } from './oauth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { RabbitmqService } from './rabbitmq.service';
import { DoctorsConsumer } from './doctors.consumer';
import { ClinicsConsumer } from './clinics.consumer';
import { EmployersConsumer } from './employers.consumer';
import { EmployerMemberActivatedConsumer } from './employer-member-activated.consumer';
import { AdminOnboardingService } from './admin-onboarding.service';
import { DoctorReferralsService } from './doctor-referrals.service';
import { ReferralsConsumer } from './referrals.consumer';
import { EmployersHttpClient } from './employers-http.client';

@Module({
  imports: [PrismaModule, NotificationsModule],
  controllers: [
    AuthController,
    OAuthController,
    AdminOnboardingController,
    AdminAccountsController,
    AdminCommercialAccountsController,
    DoctorReferralsController,
  ],
  providers: [
    AuthService,
    RabbitmqService,
    DoctorsConsumer,
    ReferralsConsumer,
    ClinicsConsumer,
    EmployersConsumer,
    EmployerMemberActivatedConsumer,
    AdminOnboardingService,
    DoctorReferralsService,
    EmployersHttpClient,
  ],
})
export class AuthModule {}
