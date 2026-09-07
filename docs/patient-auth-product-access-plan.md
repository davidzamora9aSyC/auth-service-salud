# Patient auth product access plan — `auth-service-salud`

## Alcance

Este documento aterriza, para `auth-service-salud`, la planificación de migración descrita en `docs/patient-auth-product-access-migration-plan.md`.

## Reglas operativas

- Seguir obligatoriamente `AGENTS.md` de la raíz del repo.
- Este microservicio se corre en contenedor Docker mediante `auth-service-salud/docker-compose.yml`.
- No correr este microservicio directamente en el host.
- Cualquier validación de Prisma o de runtime debe ejecutarse dentro del contenedor.

## Objetivo del servicio

Emitir sesiones de paciente con:

- `Account.role = MEMBER`
- contexto efectivo:
  - `activeProduct = PATIENT_PORTAL`
  - `activeProductRole = PATIENT`
  - `productSubjectId = patientId`
  - `patientId = patientId`

Sin usar `role = PATIENT` como rol principal del token.

## Estado actual

- Ya crea pacientes nuevos con `Account.role = MEMBER`.
- Ya provisiona:
  - `AccountRoleProfile(PATIENT)`
  - `AccountProductAccess(PATIENT_PORTAL, PATIENT)`
- Todavía emite sesiones legacy con `sessionRole = PATIENT` en login, register, refresh, MFA, OAuth y `selectProductAccess`.

## Cambios a implementar

### 1. Token issuance

- Refactor de `src/auth/auth.service.ts` en `issueTokens(...)`.
- Separar:
  - rol base de cuenta/sesión
  - contexto de producto
  - resolución de `patientId`
- Para portal paciente:
  - `role = MEMBER`
  - `activeProduct = PATIENT_PORTAL`
  - `activeProductRole = PATIENT`
  - `productSubjectId = patientId`
  - `productAccessStatus = ACTIVE`
  - `patientId = patientId`

### 2. Selección de producto

- Ajustar `resolveSessionRoleForProductAccess(...)`.
- `PATIENT_PORTAL/PATIENT` ya no debe mapear a `PATIENT`.
- Debe conservar `MEMBER` y mover la semántica paciente al contexto de producto.

### 3. Login y refresh

- `login(...)`
  - `role = PATIENT` pasa a significar “quiero entrar al portal paciente”.
  - si la cuenta tiene acceso paciente válido, emitir token `MEMBER + patient product context`.
- `refresh(...)`
  - debe reconstruir exactamente el contexto de producto sin degradarlo a `PATIENT`.

### 4. `selectProductAccess(...)`

- Si se selecciona `PATIENT_PORTAL/PATIENT`, el token emitido debe seguir con `role = MEMBER`.

### 5. Compatibilidad temporal

- `getAvailableRoles(...)` puede seguir exponiendo `PATIENT` como compat visual legacy, pero no como fuente de verdad.
- La API canónica para portal paciente debe ser:
  - `GET /auth/product-access/me`
  - `POST /auth/product-access/select`

## Decisiones de seguridad

- No emitir sesión paciente si falta `AccountProductAccess(PATIENT_PORTAL, PATIENT)`.
- No emitir sesión paciente si el access está `DISABLED` o `SUSPENDED`.
- `PENDING` solo con caso explícito de onboarding.
- El `patientId` nunca sale del front; siempre sale de role profile / product access.

## Criterio de terminado

- Login paciente devuelve `account.role = MEMBER`.
- `selectProductAccess(PATIENT_PORTAL/PATIENT)` devuelve token `MEMBER + product context`.
- Refresh, MFA y OAuth preservan el mismo contexto.

