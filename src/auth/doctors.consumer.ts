import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Channel, Connection, ConsumeMessage, connect } from 'amqplib';
import { PrismaService } from '../prisma/prisma.service';
import { NotificationsService } from '../notifications/notifications.service';
import { AccountRole, OnboardingStatus } from '@prisma/client';

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
export class DoctorsConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(DoctorsConsumer.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private isShuttingDown = false;
  private readonly reconnectDelayMs = 5000;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
    private readonly notifications: NotificationsService,
  ) {}

  async onModuleInit() {
    await this.connectWithRetry();
  }

  private async connectWithRetry() {
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
      await this.channel.assertExchange(exchange, 'topic', { durable: true });
      await assertQueueForConsume(this.connection, this.channel, queue);
      await this.channel.bindQueue(queue, exchange, 'doctors.profile_completed');
      await this.channel.bindQueue(queue, exchange, 'doctors.onboarding_completed');
      await this.channel.bindQueue(queue, exchange, 'doctors.phone_updated');
      await this.channel.prefetch(5);
      await this.channel.consume(queue, (msg) => this.handleMessage(msg), {
        noAck: false,
      });
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

      if (
        payload.type !== 'DoctorProfileCompleted' &&
        payload.type !== 'DoctorOnboardingCompleted' &&
        payload.type !== 'DoctorPhoneUpdated'
      ) {
        this.channel.ack(msg);
        return;
      }

      const authUserId = String(payload.data?.authUserId ?? '');
      const doctorId = String(payload.data?.doctorId ?? '');
      if (payload.type === 'DoctorPhoneUpdated') {
        const phoneNumber = String(payload.data?.phoneNumber ?? '').trim();
        if (!authUserId || !phoneNumber) {
          this.channel.ack(msg);
          return;
        }
        const updated = await this.prisma.account.updateMany({
          where: {
            id: authUserId,
            role: AccountRole.DOCTOR,
          },
          data: {
            phoneNumber,
          },
        });
        if (updated.count === 0) {
          this.logger.warn(`No se actualizo telefono para ${authUserId}`);
        }
        this.channel.ack(msg);
        return;
      }

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

      const account = await this.prisma.account.findFirst({
        where: {
          id: authUserId,
          role: AccountRole.DOCTOR,
        },
        select: {
          email: true,
        },
      });

      const destinationEmail = account?.email?.trim().toLowerCase();
      if (destinationEmail) {
        try {
          const name =
            (await this.fetchDoctorNameByAuthUserId(authUserId)) ?? 'Especialista';
          await this.notifications.sendDoctorOnboardingWelcomeEmail({
            email: destinationEmail,
            name,
          });
        } catch (error) {
          this.logger.warn(
            `No se pudo enviar bienvenida por correo a ${destinationEmail}: ${error instanceof Error ? error.message : error}`,
          );
        }
      }

      this.channel.ack(msg);
    } catch (error) {
      this.logger.error('Error procesando evento', error as Error);
      this.channel.ack(msg);
    }
  }

  private async fetchDoctorNameByAuthUserId(authUserId: string) {
    const base =
      this.config.get<string>('DOCTORS_INTERNAL_BASE_URL') ??
      'http://doctors-service:3009/doctorsms';
    try {
      const response = await fetch(
        `${base.replace(/\/$/, '')}/doctors/me?authUserId=${encodeURIComponent(authUserId)}`,
        { headers: { 'x-role': 'SYSTEM' } },
      );
      if (!response.ok) return null;
      const data = (await response.json()) as { fullName?: string | null };
      return data.fullName?.trim() || null;
    } catch {
      return null;
    }
  }
}
