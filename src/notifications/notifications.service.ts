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
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/internal/whatsapp/send-template`;
    const templateKey =
      this.config.get<string>('WELCOME_WHATSAPP_TEMPLATE_KEY') ??
      'MEUSALUD_WELCOME';
    const fallbackName = 'Usuario MeuSalud';
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
        `Fallo el envio del WhatsApp de bienvenida a ${input.phoneNumber}: ${message}`,
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
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
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
        `Fallo el envio del WhatsApp de recuperacion a ${input.phoneNumber}: ${message}`,
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
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }

    const endpoint = `${baseUrl.replace(/\/$/, '')}/email/messages`;
    const expiresMinutes = Math.max(1, Math.ceil((input.ttlSeconds ?? 600) / 60));
    const subject = 'Recuperacion de contrasena | MeuDoc';

    const supportEmail =
      this.config.get<string>('SUPPORT_EMAIL') ?? 'comunicaciones@meudoc.co';
    const portalUrl =
      this.config.get<string>('PATIENT_PORTAL_URL') ??
      this.config.get<string>('DOCTOR_PORTAL_URL') ??
      'https://meudoc.co';
    const headerImageUrl =
      this.config.get<string>('RECOVERY_EMAIL_HEADER_IMAGE_URL') ??
      this.config.get<string>('NOTIFICATIONS_BRAND_IMAGE_URL') ??
      '';

    const safeName = this.escapeHtml(input.name);
    const safeCode = this.escapeHtml(input.code);
    const safeLink = this.escapeHtml(input.link);
    const safeSupport = this.escapeHtml(supportEmail);
    const safePortal = this.escapeHtml(portalUrl);
    const safeMinutes = this.escapeHtml(String(expiresMinutes));

    const text = [
      `Hola ${input.name},`,
      '',
      'Recibimos una solicitud para cambiar la contrasena de tu cuenta en MeuDoc.',
      `Tu codigo de recuperacion es: ${input.code}`,
      `Este codigo vence en ${expiresMinutes} minuto(s).`,
      '',
      `Puedes continuar el proceso aqui: ${input.link}`,
      '',
      'Si no solicitaste este cambio, ignora este mensaje.',
      `Soporte: ${supportEmail}`,
      '',
      'Equipo MeuDoc',
      portalUrl,
    ].join('\n');

    const html = `
      <div style="margin:0;padding:24px;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
        <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
          ${
            headerImageUrl
              ? `<img src="${this.escapeHtml(headerImageUrl)}" alt="MeuDoc" style="width:100%;max-height:220px;object-fit:cover;display:block;" />`
              : ''
          }
          <div style="padding:24px;">
            <h1 style="margin:0 0 12px 0;font-size:24px;line-height:1.25;">Recuperar contrasena</h1>
            <p style="margin:0 0 10px 0;font-size:15px;">Hola <strong>${safeName}</strong>,</p>
            <p style="margin:0 0 10px 0;font-size:15px;">Recibimos una solicitud para cambiar la contrasena de tu cuenta en MeuDoc.</p>
            <p style="margin:0 0 12px 0;font-size:15px;">Tu codigo de recuperacion es:</p>
            <div style="display:inline-block;background:#0f172a;color:#ffffff;padding:10px 14px;border-radius:10px;font-size:24px;font-weight:700;letter-spacing:4px;">${safeCode}</div>
            <p style="margin:12px 0 0 0;font-size:14px;">Este codigo vence en <strong>${safeMinutes} minuto(s)</strong>.</p>
            <p style="margin:14px 0 0 0;">
              <a href="${safeLink}" style="display:inline-block;background:#059669;color:#ffffff;text-decoration:none;padding:11px 16px;border-radius:10px;font-weight:700;">Continuar recuperacion</a>
            </p>
            <p style="margin:16px 0 0 0;font-size:13px;color:#475569;">Si no solicitaste este cambio, ignora este mensaje.</p>
            <p style="margin:8px 0 0 0;font-size:13px;color:#475569;">Soporte: ${safeSupport}</p>
            <p style="margin:12px 0 0 0;font-size:13px;color:#475569;">Equipo MeuDoc<br />${safePortal}</p>
          </div>
        </div>
      </div>
    `.trim();

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
        `Fallo el envio del correo de recuperacion a ${input.email}: ${message}`,
        error as Error,
      );
    }
  }

  async sendPhoneChangeWhatsapp(input: {
    phoneNumber: string;
    name: string;
    code: string;
    ttlSeconds?: number;
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006/communicationms';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/internal/whatsapp/send-template`;
    const templateKey =
      this.config.get<string>('PHONE_CHANGE_WHATSAPP_TEMPLATE_KEY') ??
      this.config.get<string>('PASSWORD_RESET_TEMPLATE_KEY') ??
      'PASSWORD_RESET';

    const payload: WhatsappPayload = {
      to_e164: input.phoneNumber,
      template_code: templateKey,
      variables: {
        name: input.name,
        code: input.code,
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
        `Fallo el envio del WhatsApp de cambio de telefono a ${input.phoneNumber}: ${message}`,
        error as Error,
      );
    }
  }

  async sendPhoneChangeEmail(input: {
    email: string;
    name: string;
    code: string;
    ttlSeconds?: number;
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006/communicationms';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }

    const endpoint = `${baseUrl.replace(/\/$/, '')}/email/messages`;
    const expiresMinutes = Math.max(1, Math.ceil((input.ttlSeconds ?? 600) / 60));
    const subject = 'Verificacion de cambio de telefono | MeuDoc';

    const supportEmail =
      this.config.get<string>('SUPPORT_EMAIL') ?? 'comunicaciones@meudoc.co';
    const portalUrl =
      this.config.get<string>('PATIENT_PORTAL_URL') ??
      this.config.get<string>('DOCTOR_PORTAL_URL') ??
      'https://meudoc.co';

    const safeName = this.escapeHtml(input.name);
    const safeCode = this.escapeHtml(input.code);
    const safeSupport = this.escapeHtml(supportEmail);
    const safePortal = this.escapeHtml(portalUrl);
    const safeMinutes = this.escapeHtml(String(expiresMinutes));

    const text = [
      `Hola ${input.name},`,
      '',
      'Recibimos una solicitud para cambiar el telefono asociado a tu cuenta en MeuDoc.',
      `Tu codigo de verificacion es: ${input.code}`,
      `Este codigo vence en ${expiresMinutes} minuto(s).`,
      '',
      'Si no solicitaste este cambio, ignora este mensaje.',
      `Soporte: ${supportEmail}`,
      '',
      'Equipo MeuDoc',
      portalUrl,
    ].join('\n');

    const html = `
      <div style="margin:0;padding:24px;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
        <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
          <div style="padding:24px;">
            <h1 style="margin:0 0 12px 0;font-size:24px;line-height:1.25;">Confirmar cambio de telefono</h1>
            <p style="margin:0 0 10px 0;font-size:15px;">Hola <strong>${safeName}</strong>,</p>
            <p style="margin:0 0 12px 0;font-size:15px;">Recibimos una solicitud para cambiar el telefono asociado a tu cuenta en MeuDoc. Si deseas continuar, usa este codigo:</p>
            <div style="display:inline-block;background:#0f172a;color:#ffffff;padding:10px 14px;border-radius:10px;font-size:24px;font-weight:700;letter-spacing:4px;">${safeCode}</div>
            <p style="margin:12px 0 0 0;font-size:14px;">Este codigo vence en <strong>${safeMinutes} minuto(s)</strong>.</p>
            <p style="margin:16px 0 0 0;font-size:13px;color:#475569;">Si no solicitaste este cambio, ignora este mensaje.</p>
            <p style="margin:8px 0 0 0;font-size:13px;color:#475569;">Soporte: ${safeSupport}</p>
            <p style="margin:12px 0 0 0;font-size:13px;color:#475569;">Equipo MeuDoc<br />${safePortal}</p>
          </div>
        </div>
      </div>
    `.trim();

    const payload: EmailPayload = {
      to: input.email,
      templateKey: 'PHONE_CHANGE',
      subject,
      text,
      html,
      metadata: {
        flow: 'phone-change',
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
        `Fallo el envio del correo de cambio de telefono a ${input.email}: ${message}`,
        error as Error,
      );
    }
  }

  async sendDoctorOnboardingWelcomeEmail(input: { email: string; name: string }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006/communicationms';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }

    const endpoint = `${baseUrl.replace(/\/$/, '')}/email/messages`;
    const subject = 'Bienvenido a MeuDoc Pro';

    const supportEmail =
      this.config.get<string>('SUPPORT_EMAIL') ?? 'comunicaciones@meudoc.co';
    const portalUrl =
      this.config.get<string>('DOCTOR_PORTAL_URL') ?? 'https://meudoc.co';
    const headerImageUrl =
      this.config.get<string>('WELCOME_EMAIL_HEADER_IMAGE_URL') ??
      this.config.get<string>('NOTIFICATIONS_BRAND_IMAGE_URL') ??
      '';

    const safeName = this.escapeHtml(input.name);
    const safeSupport = this.escapeHtml(supportEmail);
    const safePortal = this.escapeHtml(portalUrl);

    const text = [
      `Hola ${input.name},`,
      '',
      'Tu perfil profesional en MeuDoc ya esta activo.',
      'Ya puedes gestionar tu agenda, pacientes y reportes desde tu panel.',
      '',
      `Ingresa aqui: ${portalUrl}`,
      '',
      'Si necesitas ayuda, escribenos a:',
      supportEmail,
      '',
      'Equipo MeuDoc',
    ].join('\n');

    const html = `
      <div style="margin:0;padding:0;background:#eef2f7;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
        <div style="background:linear-gradient(135deg,#0f766e 0%,#0ea5e9 55%,#6366f1 100%);padding:28px 20px;">
          <div style="max-width:680px;margin:0 auto;">
            <p style="margin:0;color:#e0f2fe;font-size:12px;letter-spacing:1.5px;text-transform:uppercase;">MeuDoc Pro</p>
            <h1 style="margin:8px 0 0 0;color:#ffffff;font-size:28px;line-height:1.2;">Tu perfil ya esta activo</h1>
            <p style="margin:8px 0 0 0;color:#e0f2fe;font-size:15px;">Todo listo para empezar a recibir pacientes.</p>
          </div>
        </div>
        <div style="max-width:680px;margin:0 auto;padding:0 20px 28px;">
          <div style="margin-top:-24px;background:#ffffff;border:1px solid #e2e8f0;border-radius:16px;overflow:hidden;box-shadow:0 12px 24px rgba(15,23,42,0.08);">
            ${
              headerImageUrl
                ? `<img src="${this.escapeHtml(headerImageUrl)}" alt="MeuDoc" style="width:100%;max-height:220px;object-fit:cover;display:block;" />`
                : ''
            }
            <div style="padding:28px;">
              <p style="margin:0 0 12px 0;font-size:16px;">Hola <strong>${safeName}</strong>,</p>
              <p style="margin:0 0 16px 0;font-size:15px;color:#1e293b;">Tu perfil profesional en MeuDoc ya esta activo. Desde tu panel puedes gestionar tu agenda, pacientes y reportes.</p>
              <div style="display:flex;gap:12px;flex-wrap:wrap;margin:0 0 18px 0;">
                <div style="flex:1 1 180px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px 14px;">
                  <p style="margin:0 0 6px 0;font-weight:700;font-size:13px;color:#0f172a;">Agenda en vivo</p>
                  <p style="margin:0;font-size:12px;color:#475569;">Controla tu disponibilidad y horarios.</p>
                </div>
                <div style="flex:1 1 180px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px 14px;">
                  <p style="margin:0 0 6px 0;font-weight:700;font-size:13px;color:#0f172a;">Pacientes</p>
                  <p style="margin:0;font-size:12px;color:#475569;">Accede a historial y seguimientos.</p>
                </div>
                <div style="flex:1 1 180px;background:#f8fafc;border:1px solid #e2e8f0;border-radius:12px;padding:12px 14px;">
                  <p style="margin:0 0 6px 0;font-weight:700;font-size:13px;color:#0f172a;">Reportes</p>
                  <p style="margin:0;font-size:12px;color:#475569;">Visualiza tu rendimiento en minutos.</p>
                </div>
              </div>
              <a href="${safePortal}" style="display:inline-block;background:#0f766e;color:#ffffff;text-decoration:none;padding:12px 18px;border-radius:12px;font-weight:700;">Entrar a MeuDoc</a>
              <p style="margin:18px 0 0 0;font-size:12px;color:#64748b;">Si necesitas ayuda, escribenos a ${safeSupport}.</p>
            </div>
          </div>
          <p style="margin:18px 0 0 0;text-align:center;font-size:11px;color:#94a3b8;">Equipo MeuDoc</p>
        </div>
      </div>
    `.trim();

    const payload: EmailPayload = {
      to: input.email,
      templateKey: 'DOCTOR_ONBOARDING_WELCOME_EMAIL',
      subject,
      text,
      html,
      metadata: {
        flow: 'doctor-onboarding-complete',
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
        `Fallo el envio del correo de bienvenida a ${input.email}: ${message}`,
        error as Error,
      );
    }
  }

  async sendAccountDeletionWhatsapp(input: {
    phoneNumber: string;
    name: string;
    code: string;
    ttlSeconds?: number;
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006/communicationms';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }
    const endpoint = `${baseUrl.replace(/\/$/, '')}/internal/whatsapp/send-template`;
    const templateKey =
      this.config.get<string>('ACCOUNT_DELETION_TEMPLATE_KEY') ??
      this.config.get<string>('PASSWORD_RESET_TEMPLATE_KEY') ??
      'PASSWORD_RESET';

    const payload: WhatsappPayload = {
      to_e164: input.phoneNumber,
      template_code: templateKey,
      variables: {
        name: input.name,
        code: input.code,
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
        `Fallo el envio del WhatsApp de borrado de cuenta a ${input.phoneNumber}: ${message}`,
        error as Error,
      );
    }
  }

  async sendAccountDeletionEmail(input: {
    email: string;
    name: string;
    code: string;
    ttlSeconds?: number;
  }) {
    const baseUrl =
      this.config.get<string>('NOTIFICATIONS_SERVICE_URL') ??
      'http://communication-service:3006/communicationms';
    if (!baseUrl) {
      this.logger.warn('NOTIFICATIONS_SERVICE_URL no esta configurado');
      return;
    }

    const endpoint = `${baseUrl.replace(/\/$/, '')}/email/messages`;
    const expiresMinutes = Math.max(1, Math.ceil((input.ttlSeconds ?? 600) / 60));
    const subject = 'Confirmacion para borrar cuenta | MeuDoc';
    const supportEmail =
      this.config.get<string>('SUPPORT_EMAIL') ?? 'comunicaciones@meudoc.co';
    const portalUrl =
      this.config.get<string>('PATIENT_PORTAL_URL') ??
      this.config.get<string>('DOCTOR_PORTAL_URL') ??
      'https://meudoc.co';

    const safeName = this.escapeHtml(input.name);
    const safeCode = this.escapeHtml(input.code);
    const safeSupport = this.escapeHtml(supportEmail);
    const safePortal = this.escapeHtml(portalUrl);
    const safeMinutes = this.escapeHtml(String(expiresMinutes));

    const text = [
      `Hola ${input.name},`,
      '',
      'Recibimos una solicitud para borrar tu cuenta de MeuDoc.',
      `Tu codigo de confirmacion es: ${input.code}`,
      `Este codigo vence en ${expiresMinutes} minuto(s).`,
      '',
      'Si no solicitaste este proceso, ignora este mensaje.',
      `Soporte: ${supportEmail}`,
      '',
      'Equipo MeuDoc',
      portalUrl,
    ].join('\n');

    const html = `
      <div style="margin:0;padding:24px;background:#f1f5f9;font-family:Arial,Helvetica,sans-serif;color:#0f172a;">
        <div style="max-width:620px;margin:0 auto;background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;overflow:hidden;">
          <div style="padding:24px;">
            <h1 style="margin:0 0 12px 0;font-size:24px;line-height:1.25;">Confirmar borrado de cuenta</h1>
            <p style="margin:0 0 10px 0;font-size:15px;">Hola <strong>${safeName}</strong>,</p>
            <p style="margin:0 0 12px 0;font-size:15px;">Recibimos una solicitud para borrar tu cuenta de MeuDoc. Si deseas continuar, usa este codigo:</p>
            <div style="display:inline-block;background:#7f1d1d;color:#ffffff;padding:10px 14px;border-radius:10px;font-size:24px;font-weight:700;letter-spacing:4px;">${safeCode}</div>
            <p style="margin:12px 0 0 0;font-size:14px;">Este codigo vence en <strong>${safeMinutes} minuto(s)</strong>.</p>
            <p style="margin:16px 0 0 0;font-size:13px;color:#475569;">Si no solicitaste este proceso, ignora este mensaje.</p>
            <p style="margin:8px 0 0 0;font-size:13px;color:#475569;">Soporte: ${safeSupport}</p>
            <p style="margin:12px 0 0 0;font-size:13px;color:#475569;">Equipo MeuDoc<br />${safePortal}</p>
          </div>
        </div>
      </div>
    `.trim();

    const payload: EmailPayload = {
      to: input.email,
      templateKey: 'ACCOUNT_DELETION',
      subject,
      text,
      html,
      metadata: {
        flow: 'account-deletion',
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
        `Fallo el envio del correo de borrado de cuenta a ${input.email}: ${message}`,
        error as Error,
      );
    }
  }

  private escapeHtml(value: string) {
    return value
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
}
