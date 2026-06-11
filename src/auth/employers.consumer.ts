import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Channel, Connection, ConsumeMessage, connect } from 'amqplib';
import { AccountRole, OnboardingStatus, ProductCode, ProductRole } from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class EmployersConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EmployersConsumer.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async onModuleInit() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, consumer de empresas deshabilitado');
      return;
    }

    const queue =
      this.config.get<string>('RABBITMQ_QUEUE_AUTH_EMPLOYERS') ??
      'auth.q.employers';
    const exchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_EMPLOYERS') ??
      'employers.events';

    try {
      this.connection = await connect(url);
      this.channel = await this.connection.createChannel();
      await this.channel.assertExchange(exchange, 'topic', { durable: true });
      await this.channel.assertQueue(queue, { durable: true });
      await this.channel.bindQueue(queue, exchange, 'employers.profile_completed');
      await this.channel.prefetch(5);
      await this.channel.consume(queue, (msg) => this.handleMessage(msg), {
        noAck: false,
      });
      this.logger.log(`Escuchando ${queue}`);
    } catch (error) {
      this.logger.error('No se pudo conectar a RabbitMQ', error as Error);
    }
  }

  async onModuleDestroy() {
    await this.channel?.close().catch(() => undefined);
    await this.connection?.close().catch(() => undefined);
  }

  private async handleMessage(msg: ConsumeMessage | null) {
    if (!msg || !this.channel) {
      return;
    }

    try {
      const payload = JSON.parse(msg.content.toString()) as {
        type?: string;
        data?: Record<string, unknown>;
      };

      if (payload.type !== 'EmployerProfileCompleted') {
        this.channel.ack(msg);
        return;
      }

      const authUserId = String(payload.data?.authUserId ?? '');
      const employerId = String(payload.data?.employerId ?? '');
      if (!authUserId || !employerId) {
        this.channel.ack(msg);
        return;
      }

      const completed = {
        onboardingStatus: OnboardingStatus.COMPLETE,
        subjectId: employerId,
      };

      await this.prisma.$transaction([
        this.prisma.accountRoleProfile.updateMany({
          where: { accountId: authUserId, role: AccountRole.EMPLOYER },
          data: completed,
        }),
        this.prisma.account.updateMany({
          where: { id: authUserId, role: AccountRole.EMPLOYER },
          data: completed,
        }),
      ]);

      await this.prisma.accountProductAccess.updateMany({
        where: {
          accountId: authUserId,
          product: ProductCode.MEUDOC_EMPLOYER,
          role: ProductRole.EMPLOYER_ADMIN,
        },
        data: { subjectId: employerId },
      });

      this.channel.ack(msg);
    } catch (error) {
      this.logger.error('Error procesando evento de empresa', error as Error);
      this.channel.ack(msg);
    }
  }
}
