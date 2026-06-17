import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Channel, Connection, connect } from 'amqplib';
import { randomUUID } from 'node:crypto';

type AuthEventPayload = {
  authUserId: string;
  role: string;
  doctorId?: string;
  email?: string;
  phoneNumber?: string;
  firstName?: string;
  lastName?: string;
  inviteToken?: string;
  preferredPlanCode?: string;
};

type DoctorEventPayload = {
  doctorId: string;
};

@Injectable()
export class RabbitmqService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RabbitmqService.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;
  private authExchange = 'auth.events';
  private doctorsExchange = 'doctors.events';
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private isConnecting = false;
  private isShuttingDown = false;
  private readonly reconnectDelayMs = 5000;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    this.authExchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_AUTH') ?? 'auth.events';
    this.doctorsExchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_DOCTORS') ?? 'doctors.events';
    await this.ensureChannel();
  }

  async onModuleDestroy() {
    this.isShuttingDown = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    await this.cleanupConnection();
  }

  private async cleanupConnection() {
    await this.channel?.close().catch(() => undefined);
    await this.connection?.close().catch(() => undefined);
    this.channel = null;
    this.connection = null;
  }

  private async connectWithRetry() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, eventos deshabilitados');
      return;
    }
    if (this.isConnecting || this.isShuttingDown) {
      return;
    }
    this.isConnecting = true;
    try {
      await this.cleanupConnection();
      this.connection = await connect(url);
      this.channel = await this.connection.createChannel();
      await this.channel.assertExchange(this.authExchange, 'topic', {
        durable: true,
      });
      await this.channel.assertExchange(this.doctorsExchange, 'topic', {
        durable: true,
      });
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
      this.logger.log('Conectado a RabbitMQ');
    } catch (error) {
      this.logger.warn(
        `No se pudo conectar a RabbitMQ, reintentando en ${this.reconnectDelayMs}ms: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      this.scheduleReconnect();
    } finally {
      this.isConnecting = false;
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

  private async ensureChannel() {
    if (this.channel) {
      return true;
    }
    await this.connectWithRetry();
    return Boolean(this.channel);
  }

  async publishAuthEvent(event: {
    type:
      | 'AuthUserRegistered'
      | 'DoctorOnboardingInviteCreated'
      | 'EmployerMemberLinked'
      | 'DoctorAccountRegistered';
    routingKey: string;
    data: Partial<AuthEventPayload> & Record<string, unknown>;
    correlationId?: string;
  }) {
    if (!(await this.ensureChannel()) || !this.channel) {
      this.logger.warn(
        `RabbitMQ channel no disponible. Evento omitido: ${event.type} (${event.routingKey})`,
      );
      return;
    }
    const payload = {
      id: randomUUID(),
      type: event.type,
      version: 1,
      occurredAt: new Date().toISOString(),
      producer: 'auth-service',
      correlationId: event.correlationId,
      data: event.data,
    };
    try {
      this.logger.log(
        `Publicando evento ${event.type} -> ${event.routingKey} (${this.authExchange}) payload=${JSON.stringify(
          payload,
        )}`,
      );
      this.channel.publish(
        this.authExchange,
        event.routingKey,
        Buffer.from(JSON.stringify(payload)),
        {
          persistent: true,
          contentType: 'application/json',
        },
      );
    } catch (error) {
      this.logger.warn(
        `No se pudo publicar evento ${event.type} (${event.routingKey}): ${error instanceof Error ? error.message : error}`,
      );
    }
  }

  async publishDoctorEvent(event: {
    type: 'DoctorDeleted';
    routingKey: string;
    data: DoctorEventPayload;
    correlationId?: string;
  }) {
    if (!(await this.ensureChannel()) || !this.channel) {
      this.logger.warn(
        `RabbitMQ channel no disponible. Evento omitido: ${event.type} (${event.routingKey})`,
      );
      return;
    }
    const payload = {
      id: randomUUID(),
      type: event.type,
      version: 1,
      occurredAt: new Date().toISOString(),
      producer: 'auth-service',
      correlationId: event.correlationId,
      data: event.data,
    };
    try {
      this.channel.publish(
        this.doctorsExchange,
        event.routingKey,
        Buffer.from(JSON.stringify(payload)),
        {
          persistent: true,
          contentType: 'application/json',
        },
      );
    } catch (error) {
      this.logger.warn(
        `No se pudo publicar evento ${event.type} (${event.routingKey}): ${error instanceof Error ? error.message : error}`,
      );
    }
  }
}
