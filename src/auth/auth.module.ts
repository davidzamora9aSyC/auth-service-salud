import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { OAuthController } from './oauth.controller';
import { PrismaModule } from '../prisma/prisma.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { RabbitmqService } from './rabbitmq.service';
import { DoctorsConsumer } from './doctors.consumer';

@Module({
  imports: [PrismaModule, NotificationsModule],
  controllers: [AuthController, OAuthController],
  providers: [AuthService, RabbitmqService, DoctorsConsumer],
})
export class AuthModule {}
