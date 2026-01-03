import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import amqplib, { Channel, Connection } from 'amqplib';
import { randomUUID } from 'node:crypto';

type AuthEventPayload = {
  authUserId: string;
  role: string;
  doctorId?: string;
  email?: string;
  phoneNumber?: string;
};

@Injectable()
export class RabbitmqService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RabbitmqService.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;

  constructor(private readonly config: ConfigService) {}

  async onModuleInit() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, eventos deshabilitados');
      return;
    }
    try {
      this.connection = await amqplib.connect(url);
      this.channel = await this.connection.createChannel();
      const exchange =
        this.config.get<string>('RABBITMQ_EXCHANGE_AUTH') ?? 'auth.events';
      await this.channel.assertExchange(exchange, 'topic', {
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
    type: 'AuthUserRegistered';
    routingKey: string;
    data: AuthEventPayload;
    correlationId?: string;
  }) {
    if (!this.channel) {
      return;
    }
    const exchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_AUTH') ?? 'auth.events';
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
      exchange,
      event.routingKey,
      Buffer.from(JSON.stringify(payload)),
      {
        persistent: true,
        contentType: 'application/json',
      },
    );
  }
}
