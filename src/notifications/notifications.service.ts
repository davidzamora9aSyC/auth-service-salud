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

type EmailPayload = {
  to: string;
  templateKey: string;
  subject: string;
  text: string;
  html: string;
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
      'http://communication-service:3006/communicationms';
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
      'http://communication-service:3006/communicationms';
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

  async sendPasswordRecoveryEmail(input: {
    email: string;
    name: string;
    code: string;
    link: string;
    ttlSeconds?: number;
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006/communicationms';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no está configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/email/messages`;
    const expiresMinutes = Math.max(
      1,
      Math.ceil((input.ttlSeconds ?? 600) / 60),
    );
    const subject = 'Código de recuperación de contraseña';
    const text = [
      `Hola ${input.name},`,
      `Tu código de recuperación es: ${input.code}`,
      `Este código vence en ${expiresMinutes} minuto(s).`,
      `También puedes abrir: ${input.link}`,
    ].join('\n');
    const html = [
      `<p>Hola ${input.name},</p>`,
      `<p>Tu código de recuperación es: <strong>${input.code}</strong></p>`,
      `<p>Este código vence en <strong>${expiresMinutes} minuto(s)</strong>.</p>`,
      `<p>También puedes abrir este enlace: <a href="${input.link}">${input.link}</a></p>`,
    ].join('');
    const payload: EmailPayload = {
      to: input.email,
      templateKey: 'PASSWORD_RESET',
      subject,
      text,
      html,
      metadata: {
        flow: 'password-recovery',
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
        `Falló el envío del correo de recuperación a ${input.email}: ${message}`,
        error as Error,
      );
    }
  }
}
