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

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, eventos deshabilitados');
      return;
    }
    try {
      this.connection = await connect(url);
      this.channel = await this.connection.createChannel();
      this.authExchange =
        this.config.get<string>('RABBITMQ_EXCHANGE_AUTH') ?? 'auth.events';
      this.doctorsExchange =
        this.config.get<string>('RABBITMQ_EXCHANGE_DOCTORS') ?? 'doctors.events';
      await this.channel.assertExchange(this.authExchange, 'topic', {
        durable: true,
      });
      await this.channel.assertExchange(this.doctorsExchange, 'topic', {
        durable: true,
      });
    } catch (error) {
      this.logger.error('No se pudo conectar a RabbitMQ', error as Error);
    }
  }

  async onModuleDestroy() {
    await this.channel?.close().catch(() => undefined);
    await this.connection?.close().catch(() => undefined);
  }

  async publishAuthEvent(event: {
    type: 'AuthUserRegistered' | 'DoctorOnboardingInviteCreated';
    routingKey: string;
    data: Partial<AuthEventPayload>;
    correlationId?: string;
  }) {
    if (!this.channel) {
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
    if (!this.channel) {
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
    this.channel.publish(
      this.doctorsExchange,
      event.routingKey,
      Buffer.from(JSON.stringify(payload)),
      {
        persistent: true,
        contentType: 'application/json',
      },
    );
  }
}
