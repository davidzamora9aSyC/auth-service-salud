import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import amqplib, { Channel, Connection, ConsumeMessage } from 'amqplib';
import { PrismaService } from '../prisma/prisma.service';
import { AccountRole, OnboardingStatus } from '@prisma/client';

@Injectable()
export class DoctorsConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DoctorsConsumer.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {}

  async onModuleInit() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, consumer deshabilitado');
      return;
    }

    const queue =
      this.config.get<string>('RABBITMQ_QUEUE_AUTH_DOCTORS') ??
      'auth.q.doctors';
    const exchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_DOCTORS') ??
      'doctors.events';

    try {
      this.connection = await amqplib.connect(url);
      this.channel = await this.connection.createChannel();
      await this.channel.assertExchange(exchange, 'topic', { durable: true });
      await this.channel.assertQueue(queue, { durable: true });
      await this.channel.bindQueue(queue, exchange, 'doctors.profile_completed');
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

      if (payload.type !== 'DoctorProfileCompleted') {
        this.channel.ack(msg);
        return;
      }

      const authUserId = String(payload.data?.authUserId ?? '');
      const doctorId = String(payload.data?.doctorId ?? '');
      if (!authUserId || !doctorId) {
        this.channel.ack(msg);
        return;
      }

      const updated = await this.prisma.account.updateMany({
        where: {
          id: authUserId,
          role: AccountRole.DOCTOR,
          doctorId,
        },
        data: { onboardingStatus: OnboardingStatus.COMPLETE },
      });

      if (updated.count === 0) {
        this.logger.warn(`No se actualizo onboarding para ${authUserId}`);
      }

      this.channel.ack(msg);
    } catch (error) {
      this.logger.error('Error procesando evento', error as Error);
      this.channel.ack(msg);
    }
  }
}
