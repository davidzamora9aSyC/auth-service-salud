import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Channel, Connection, ConsumeMessage, connect } from 'amqplib';
import { DoctorReferralsService } from './doctor-referrals.service';

const queueAssertOptions = (queue: string) => ({
  durable: true,
  arguments: {
    'x-dead-letter-exchange': 'deadletter',
    'x-dead-letter-routing-key': `${queue}.dlq`,
  },
});

const amqpErrorCode = (error: unknown) =>
  error && typeof error === 'object' && 'code' in error
    ? (error as { code?: number }).code
    : undefined;

const assertQueueForConsume = async (
  connection: Connection,
  channel: Channel,
  queue: string,
) => {
  const checkChannel = await connection.createChannel();
  try {
    await checkChannel.checkQueue(queue);
    return;
  } catch (error) {
    if (amqpErrorCode(error) !== 404) throw error;
  } finally {
    await checkChannel.close().catch(() => undefined);
  }

  await channel.assertQueue(queue, queueAssertOptions(queue));
};

@Injectable()
export class ReferralsConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ReferralsConsumer.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private isShuttingDown = false;
  private readonly reconnectDelayMs = 5000;

  constructor(
    private readonly config: ConfigService,
    private readonly referrals: DoctorReferralsService,
  ) {}

  async onModuleInit() {
    await this.connectWithRetry();
  }

  private async connectWithRetry() {
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
    const subscriptionsExchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_SUBSCRIPTIONS') ?? 'subscriptions.events';

    try {
      this.connection = await connect(url);
      this.channel = await this.connection.createChannel();
      this.connection.on('close', () => {
        if (this.isShuttingDown) return;
        this.logger.warn('Conexion RabbitMQ cerrada, reintentando...');
        this.channel = null;
        this.connection = null;
        this.scheduleReconnect();
      });
      this.connection.on('error', (error) => {
        if (this.isShuttingDown) return;
        this.logger.warn(`Error de conexion RabbitMQ: ${error.message}`);
      });
      this.channel.on('close', () => {
        if (this.isShuttingDown) return;
        this.logger.warn('Canal RabbitMQ cerrado, reintentando...');
        this.channel = null;
        this.scheduleReconnect();
      });
      this.channel.on('error', (error) => {
        if (this.isShuttingDown) return;
        this.logger.warn(`Error de canal RabbitMQ: ${error.message}`);
      });
      await this.channel.assertExchange(authExchange, 'topic', { durable: true });
      await this.channel.assertExchange(doctorsExchange, 'topic', { durable: true });
      await this.channel.assertExchange(subscriptionsExchange, 'topic', { durable: true });
      await assertQueueForConsume(this.connection, this.channel, queue);
      await this.channel.bindQueue(queue, authExchange, 'auth.doctor_account_registered');
      await this.channel.bindQueue(queue, doctorsExchange, 'doctors.onboarding_completed');
      await this.channel.bindQueue(queue, subscriptionsExchange, 'subscriptions.activated');
      await this.channel.prefetch(5);
      await this.channel.consume(queue, (msg) => this.handleMessage(msg), { noAck: false });
      this.logger.log(`Escuchando ${queue}`);
    } catch (error) {
      this.logger.warn(
        `No se pudo conectar a RabbitMQ, reintentando en ${this.reconnectDelayMs}ms: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      this.scheduleReconnect();
    }
  
  }

  private scheduleReconnect() {
    if (this.isShuttingDown || this.reconnectTimer) {
      return;
    }
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      void this.connectWithRetry();
    }, this.reconnectDelayMs);
  }

  async onModuleDestroy() {
    this.isShuttingDown = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
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
      } else if (payload.type === 'SubscriptionActivated') {
        const planCode = String(payload.data?.plan ?? '').trim();
        await this.referrals.onSubscriptionActivated(doctorId, planCode);
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
