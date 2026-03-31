import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { AdminOnboardingController } from './admin-onboarding.controller';
import { AdminAccountsController } from './admin-accounts.controller';
import { OAuthController } from './oauth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { RabbitmqService } from './rabbitmq.service';
import { DoctorsConsumer } from './doctors.consumer';
import { ClinicsConsumer } from './clinics.consumer';
import { AdminOnboardingService } from './admin-onboarding.service';

@Module({
  imports: [PrismaModule, NotificationsModule],
  controllers: [AuthController, OAuthController, AdminOnboardingController, AdminAccountsController],
  providers: [AuthService, RabbitmqService, DoctorsConsumer, ClinicsConsumer, AdminOnboardingService],
})
export class AuthModule {}
