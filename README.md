# MeuSalud Auth Service

Servicio NestJS responsable de la autenticación centralizada de MeuSalud. Expone flujos de registro, inicio de sesión y verificación en dos pasos (TOTP) tanto para pacientes como para doctores. El servicio solo gestiona credenciales e identidad técnica; los datos clínicos vivirán en microservicios separados de pacientes, doctores y consentimientos.

## Arquitectura

- **NestJS 11** con `class-validator` para exponer un API HTTP JSON (`/api/auth`).
- **Prisma + PostgreSQL** como capa de persistencia (`Account`, `RefreshToken`, `TwoFactorChallenge`).
- **Tokens firmados con RS256** leyendo la llave privada indicada por `JWT_PRIVATE_KEY_PATH`.
- **Segundo factor TOTP** para ambos roles. Los códigos se generan vía `otplib` y se verifican antes de emitir tokens cuando la cuenta tiene 2FA activo.
- Preparado para vincularse con futuros MS de pacientes/doctores a través de `subjectId` y el `role` guardado en cada cuenta.

```
MeuSalud
├── Front_MeuSalud             # Portal público donde los pacientes buscan especialistas
└── auth-service               # Este repositorio con el microservicio de autenticación
```

## Variables de entorno

Crea un `.env` a partir de `.env.example`:

```env
PORT=3000
DATABASE_URL="postgresql://meusalud_auth:meusalud_auth@localhost:5435/meusalud_auth?schema=public"
JWT_PRIVATE_KEY_PATH=/keys/jwt_rsa_private.pem
ACCESS_TOKEN_TTL=900
REFRESH_TOKEN_TTL=604800
LOGIN_CHALLENGE_TTL=300
MFA_ISSUER=MeuSalud
NOTIFICATIONS_SERVICE_URL=http://communication-service:3006
WELCOME_WHATSAPP_TEMPLATE_KEY=MEUSALUD_WELCOME
NOTIFICATIONS_TIMEOUT_MS=5000
```

- Coloca el par RSA en `auth-service/secrets` o monta la ruta deseada y referencia el archivo privado mediante `JWT_PRIVATE_KEY_PATH`.
- Si vas a correr el servicio fuera de Docker, apunta `NOTIFICATIONS_SERVICE_URL` a `http://localhost:3006`. Dentro de `docker compose` utilizamos `communication-service` como host.

## Notificaciones por WhatsApp

Este repositorio ahora incluye el microservicio `communication-service`, encargado de hablar con Meta WhatsApp Cloud API. Para tener el flujo completo en local:

1. Copia `communication-service/.env.example` a `communication-service/.env` y define tus credenciales reales de Meta (el `docker-compose.yml` usa `communication-service/.env.compose` como base; puedes editarlo o sobreescribir las variables a la hora de ejecutar).
2. Ejecuta `docker compose up --build` dentro de `auth-service`. Además de PostgreSQL y el propio `auth-service`, se levantará `communication-service` en `http://localhost:3006`.
3. El endpoint `POST /api/auth/register` guardará la cuenta y pedirá al servicio de comunicaciones que envíe un mensaje de bienvenida vía WhatsApp utilizando la plantilla `MEUSALUD_WELCOME`.

Si no configuras las credenciales de Meta, el registro seguirá funcionando y sólo verás un log informando que el canal de WhatsApp no está disponible.

## Comandos útiles

```bash
# instalar dependencias
npm install

# generar cliente prisma y aplicar migraciones
npm run prisma:generate
npm run prisma:migrate:dev -- --name init

# levantar en desarrollo
npm run start:dev

# ejecutar linter
npm run lint
```

## Docker

```bash
# construir y levantar Postgres + servicio
docker compose up --build
```

El `docker-compose.yml` expone PostgreSQL en `5435` y el API en `3000`. Monta las llaves RSA desde `./secrets` dentro del contenedor en `/keys`.

## Endpoints principales

| Método | Path | Descripción |
| --- | --- | --- |
| `POST /api/auth/register` | Crea credencial para paciente o doctor. |
| `POST /api/auth/login` | Valida email/contraseña y devuelve tokens o un `challengeId` si la cuenta tiene 2FA. |
| `POST /api/auth/login/verify` | Recibe `challengeId` + código TOTP para completar el inicio de sesión. |
| `POST /api/auth/refresh` | Gira tokens usando el refresh token vigente. |
| `POST /api/auth/logout` | Revoca el refresh token recibido. |
| `POST /api/auth/2fa/setup` | Genera secreto provisional (requiere refresh token). |
| `POST /api/auth/2fa/activate` | Confirma el TOTP y activa el segundo factor. |
| `DELETE /api/auth/2fa` | Desactiva 2FA validando un último código. |

### Flujo de autenticación en dos pasos

1. **Paciente o doctor** envía correo, contraseña y rol (`PATIENT`/`DOCTOR`).
2. Si la cuenta tiene 2FA activo, se devuelve `{ requiresTwoFactor: true, challengeId }` y se almacena un reto con TTL configurable (`LOGIN_CHALLENGE_TTL`).
3. El frontend solicita el código TOTP y lo envía a `/auth/login/verify` junto con el `challengeId`.
4. Al validar el código, el servicio emite access y refresh tokens RS256 con los claims `sub`, `role` y `subjectId` (para enlazar con los futuros MS de pacientes/doctores).

## Próximos pasos sugeridos

- Consumir este servicio desde el portal de pacientes (búsqueda por ciudad/especialidad) y desde el portal profesional, reutilizando el modo "solo inicio de sesión" que tienen los doctores.
- Crear los microservicios de Pacientes, Doctores y Consentimientos y utilizar `subjectId` como referencia cruzada.
- Publicar el JWKS público y exponer un endpoint de introspección cuando exista un API Gateway.
