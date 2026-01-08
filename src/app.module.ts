import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './auth/auth.module';
import { HealthController } from './health.controller';
import { JwksModule } from './jwks/jwks.module';
import { CollaboratorsModule } from './collaborators/collaborators.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    AuthModule,
    CollaboratorsModule,
    JwksModule,
  ],
  controllers: [HealthController],
})
export class AppModule {}
