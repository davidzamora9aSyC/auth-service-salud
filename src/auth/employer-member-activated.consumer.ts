import { Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Channel, Connection, ConsumeMessage, connect } from 'amqplib';
import { ProductRole } from '@prisma/client';
import { AuthService } from './auth.service';

@Injectable()
export class EmployerMemberActivatedConsumer implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(EmployerMemberActivatedConsumer.name);
  private connection: Connection | null = null;
  private channel: Channel | null = null;

  constructor(
    private readonly config: ConfigService,
    private readonly authService: AuthService,
  ) {}

  async onModuleInit() {
    const url = this.config.get<string>('RABBITMQ_URL');
    if (!url) {
      this.logger.warn('RABBITMQ_URL no configurado, consumer employer member deshabilitado');
      return;
    }

    const queue =
      this.config.get<string>('RABBITMQ_QUEUE_AUTH_EMPLOYER_MEMBERS') ??
      'auth.q.employer_members';
    const exchange =
      this.config.get<string>('RABBITMQ_EXCHANGE_EMPLOYERS') ??
      'employers.events';

    try {
      this.connection = await connect(url);
      this.channel = await this.connection.createChannel();
      await this.channel.assertExchange(exchange, 'topic', { durable: true });
      await this.channel.assertQueue(queue, { durable: true });
      await this.channel.bindQueue(queue, exchange, 'employers.member.activated');
      await this.channel.prefetch(5);
      await this.channel.consume(queue, (msg) => this.handleMessage(msg), {
        noAck: false,
      });
      this.logger.log(`Escuchando ${queue} (employers.member.activated)`);
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

      if (payload.type !== 'EmployerMemberActivated') {
        this.channel.ack(msg);
        return;
      }

      const authUserId = String(payload.data?.authUserId ?? '');
      const employerId = String(payload.data?.employerId ?? '');
      const productRole = String(payload.data?.productRole ?? ProductRole.EMPLOYER_BILLING);
      if (!authUserId || !employerId) {
        this.channel.ack(msg);
        return;
      }

      const role =
        productRole === ProductRole.EMPLOYER_ADMIN
          ? ProductRole.EMPLOYER_ADMIN
          : ProductRole.EMPLOYER_BILLING;

      await this.authService.grantEmployerAccess({
        accountId: authUserId,
        employerId,
        productRole: role,
      });

      this.channel.ack(msg);
    } catch (error) {
      this.logger.error('Error procesando EmployerMemberActivated', error as Error);
      this.channel.ack(msg);
    }
  }
}
