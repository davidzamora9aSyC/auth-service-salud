import {
  ConflictException,
  Injectable,
  Logger,
  ServiceUnavailableException,
} from '@nestjs/common';
import { ConfigService } from '@nestjs/config';

type PrepareFounderParams = {
  employerId: string;
  displayName: string;
  taxId: string;
  email?: string;
  phoneNumber?: string;
};

type FinalizeFounderParams = {
  employerId: string;
  authUserId: string;
};

@Injectable()
export class EmployersHttpClient {
  private readonly logger = new Logger(EmployersHttpClient.name);
  private readonly baseUrl: string;
  private readonly internalToken?: string;

  constructor(private readonly config: ConfigService) {
    this.baseUrl =
      this.config.get<string>('EMPLOYERS_BASE_URL') ??
      'http://employers-service:3041/employersms';
    this.internalToken = this.config.get<string>('INTERNAL_SERVICE_TOKEN');
  }

  async prepareFounder(params: PrepareFounderParams): Promise<{ employerId: string }> {
    return this.postJson('/employers/internal/founder/prepare', params);
  }

  async finalizeFounder(params: FinalizeFounderParams): Promise<{ ok: boolean }> {
    return this.postJson('/employers/internal/founder/finalize', params);
  }

  async rollbackFounder(employerId: string): Promise<{ ok: boolean }> {
    return this.postJson('/employers/internal/founder/rollback', { employerId });
  }

  private async postJson<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl.replace(/\/$/, '')}${path}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: this.buildHeaders(),
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      const text = await response.text();
      this.logger.error(
        `Employers request failed ${path} (status ${response.status}): ${text}`,
      );
      if (response.status === 409) {
        let message = 'No se pudo registrar la empresa';
        try {
          const parsed = JSON.parse(text) as { message?: string | string[] };
          if (typeof parsed.message === 'string') {
            message = parsed.message;
          } else if (Array.isArray(parsed.message)) {
            message = parsed.message.join(', ');
          }
        } catch {
          // keep default
        }
        throw new ConflictException(message);
      }
      throw new ServiceUnavailableException('No se pudo sincronizar con el servicio de empresas');
    }

    return (await response.json()) as T;
  }

  private buildHeaders(): Record<string, string> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };
    if (this.internalToken) {
      headers['x-internal-service-token'] = this.internalToken;
    }
    return headers;
  }
}
