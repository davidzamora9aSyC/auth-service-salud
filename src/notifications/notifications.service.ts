import { HttpService } from '@nestjs/axios';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

type WhatsappPayload = {
  to_e164: string;
  template_code: string;
  language?: string;
  variables?: Record<string, string>;
  idempotency_key?: string;
};

@Injectable()
export class NotificationsService {
  private readonly logger = new Logger(NotificationsService.name);

  constructor(
    private readonly http: HttpService,
    private readonly config: ConfigService,
  ) {}

  async sendRegistrationWhatsapp(input: { phoneNumber: string; email: string }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no está configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/internal/whatsapp/send-template`;
    const templateKey =
      this.config.get<string>('WELCOME_WHATSAPP_TEMPLATE_KEY') ??
      'MEUSALUD_WELCOME';
    const fallbackName =
      input.email.split('@')[0]?.trim() || 'Profesional MeuSalud';
    const payload: WhatsappPayload = {
      to_e164: input.phoneNumber,
      template_code: templateKey,
      variables: {
        name: fallbackName,
        email: input.email,
      },
    };

    try {
      await firstValueFrom(
        this.http.post(endpoint, payload, {
          timeout:
            this.config.get<number>('NOTIFICATIONS_TIMEOUT_MS') ?? 5000,
        }),
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Error desconocido';
      this.logger.error(
        `Falló el envío del WhatsApp de bienvenida a ${input.phoneNumber}: ${message}`,
        error as Error,
      );
    }
  }

  async sendPasswordRecoveryWhatsapp(input: {
    phoneNumber: string;
    name: string;
    code: string;
    link: string;
    ttlSeconds?: number;
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no está configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/internal/whatsapp/send-template`;
    const templateKey =
      this.config.get<string>('PASSWORD_RESET_TEMPLATE_KEY') ??
      'PASSWORD_RESET';

    const payload: WhatsappPayload = {
      to_e164: input.phoneNumber,
      template_code: templateKey,
      variables: {
        name: input.name,
        code: input.code,
        link: input.link,
        ttl: String(input.ttlSeconds ?? ''),
      },
    };

    try {
      await firstValueFrom(
        this.http.post(endpoint, payload, {
          timeout:
            this.config.get<number>('NOTIFICATIONS_TIMEOUT_MS') ?? 5000,
        }),
      );
    } catch (error) {
      const message =
        error instanceof Error ? error.message : 'Error desconocido';
      this.logger.error(
        `Falló el envío del WhatsApp de recuperación a ${input.phoneNumber}: ${message}`,
        error as Error,
      );
    }
  }
}
