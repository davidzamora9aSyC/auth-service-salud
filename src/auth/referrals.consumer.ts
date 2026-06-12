import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Channel, Connection, ConsumeMessage, connect } from 'amqplib';
import { DoctorReferralsService } from './doctor-referrals.service';

@Injectable()
export class ReferralsConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ReferralsConsumer.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;

  constructor(
    private readonly config: ConfigService,
    private readonly referrals: DoctorReferralsService,
  ) {}

  async onModuleInit() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, consumer de referidos deshabilitado');
      return;
    }

    const queue =
      this.config.get<string>('RABBITMQ_QUEUE_AUTH_REFERRALS') ?? 'auth.q.referrals';
    const authExchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_AUTH') ?? 'auth.events';
    const doctorsExchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_DOCTORS') ?? 'doctors.events';

    try {
      this.connection = await connect(url);
      this.channel = await this.connection.createChannel();
      await this.channel.assertExchange(authExchange, 'topic', { durable: true });
      await this.channel.assertExchange(doctorsExchange, 'topic', { durable: true });
      await this.channel.assertQueue(queue, { durable: true });
      await this.channel.bindQueue(queue, authExchange, 'auth.doctor_account_registered');
      await this.channel.bindQueue(queue, doctorsExchange, 'doctors.onboarding_completed');
      await this.channel.prefetch(5);
      await this.channel.consume(queue, (msg) => this.handleMessage(msg), { noAck: false });
      this.logger.log(`Escuchando ${queue}`);
    } catch (error) {
      this.logger.error('No se pudo conectar consumer de referidos a RabbitMQ', error as Error);
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
      const doctorId = String(payload.data?.doctorId ?? '').trim();
      if (!doctorId) {
        this.channel.ack(msg);
        return;
      }

      if (payload.type === 'DoctorAccountRegistered') {
        await this.referrals.onDoctorAccountRegistered(doctorId);
      } else if (payload.type === 'DoctorOnboardingCompleted') {
        await this.referrals.onDoctorOnboardingCompleted(doctorId);
      }
    } catch (error) {
      this.logger.warn(
        `No se pudo actualizar referido por evento: ${error instanceof Error ? error.message : error}`,
      );
    } finally {
      this.channel.ack(msg);
    }
  }
}
