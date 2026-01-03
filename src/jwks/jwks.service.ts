import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { createPublicKey } from 'node:crypto';
import { readFileSync } from 'node:fs';

@Injectable()
export class JwksService {
  private readonly jwks: { keys: (JsonWebKey & { kid: string; alg: string; use: string })[] };

  constructor(private readonly config: ConfigService) {
    const publicKeyPath = this.config.get<string>('JWT_PUBLIC_KEY_PATH');
    const privateKeyPath = this.config.get<string>('JWT_PRIVATE_KEY_PATH');
    if (!publicKeyPath && !privateKeyPath) {
      throw new Error('JWT_PUBLIC_KEY_PATH o JWT_PRIVATE_KEY_PATH es requerido');
    }

    const pem = readFileSync(publicKeyPath ?? privateKeyPath!);
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
