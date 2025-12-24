import { HttpService } from '@nestjs/axios';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { firstValueFrom } from 'rxjs';

type WhatsappPayload = {
  to: string;
  body?: string;
  templateKey?: string;
  variables?: Record<string, string>;
  metadata?: Record<string, unknown>;
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
    const endpoint = `${baseUrl.replace(/\/$/, '')}/whatsapp/messages`;
    const templateKey =
      this.config.get<string>('WELCOME_WHATSAPP_TEMPLATE_KEY') ??
      'MEUSALUD_WELCOME';
    const fallbackName =
      input.email.split('@')[0]?.trim() || 'Profesional MeuSalud';
    const payload: WhatsappPayload = {
      to: input.phoneNumber,
      metadata: {
        reason: 'REGISTRATION_WELCOME',
        email: input.email,
      },
    };

    if (templateKey) {
      payload.templateKey = templateKey as WhatsappPayload['templateKey'];
      payload.variables = {
        name: fallbackName,
        email: input.email,
      };
    } else {
      payload.body = `Hola ${fallbackName}, gracias por registrarte en MeuSalud. Tu usuario es ${input.email}. Cuando quieras activar el segundo factor visita el portal en Configuración > Seguridad.`;
    }

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
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no está configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/whatsapp/messages`;
    const templateKey =
      this.config.get<string>('PASSWORD_RESET_TEMPLATE_KEY') ??
      'PASSWORD_RESET';

    const payload: WhatsappPayload = {
      to: input.phoneNumber,
      templateKey: templateKey as WhatsappPayload['templateKey'],
      variables: {
        name: input.name,
        code: input.code,
        link: input.link,
      },
      metadata: {
        reason: 'PASSWORD_RECOVERY',
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
