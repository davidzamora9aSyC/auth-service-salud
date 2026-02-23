import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

@Injectable()
export class JwksService {
  private readonly jwks: { keys: (JsonWebKey & { kid: string; alg: string; use: string })[] };

  constructor(private readonly config: ConfigService) {
    const inlinePrivateKey = this.config.get<string>('JWT_PRIVATE_KEY');
    const publicKeyPath = this.config.get<string>('JWT_PUBLIC_KEY_PATH');
    const privateKeyPath = this.config.get<string>('JWT_PRIVATE_KEY_PATH');
    if (!inlinePrivateKey && !publicKeyPath && !privateKeyPath) {
      throw new Error(
        'JWT_PRIVATE_KEY, JWT_PUBLIC_KEY_PATH o JWT_PRIVATE_KEY_PATH es requerido',
      );
    }

    const pem = inlinePrivateKey?.trim()
      ? Buffer.from(inlinePrivateKey.replace(/\\n/g, '\n'), 'utf-8')
      : readFileSync(publicKeyPath ?? privateKeyPath!);
    const publicKey = createPublicKey(pem);
    const jwk = publicKey.export({ format: 'jwk' }) as JsonWebKey;
    const configuredKid = this.config.get<string>('JWT_KEY_ID');
    const kid = configuredKid ?? 'meusalud-auth';

    this.jwks = {
      keys: [
        {
          ...jwk,
          kid,
          alg: 'RS256',
          use: 'sig',
        },
      ],
    };
  }

  getJwks() {
    return this.jwks;
  }
}
