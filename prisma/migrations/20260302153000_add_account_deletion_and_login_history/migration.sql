DO $$
BEGIN
  CREATE TYPE "AccountDeletionChannel" AS ENUM ('EMAIL', 'WHATSAPP');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

DO $$
BEGIN
  CREATE TYPE "AccountDeletionAuditStatus" AS ENUM ('COMPLETED', 'PARTIAL', 'FAILED');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

DO $$
BEGIN
  CREATE TYPE "LoginEventSource" AS ENUM ('PASSWORD', 'TWO_FACTOR', 'OAUTH_GOOGLE', 'OAUTH_APPLE');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

ALTER TABLE "Account"
ADD COLUMN IF NOT EXISTS "deletedAt" TIMESTAMP(3);

CREATE TABLE IF NOT EXISTS "LoginHistory" (
  "id" TEXT NOT NULL,
  "accountId" TEXT NOT NULL,
  "role" "AccountRole" NOT NULL,
  "source" "LoginEventSource" NOT NULL,
  "ipAddress" TEXT,
  "userAgent" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "LoginHistory_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "AccountDeletionChallenge" (
  "id" TEXT NOT NULL,
  "accountId" TEXT NOT NULL,
  "channel" "AccountDeletionChannel" NOT NULL,
  "destination" TEXT NOT NULL,
  "codeHash" TEXT NOT NULL,
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "attempts" INTEGER NOT NULL DEFAULT 0,
  "maxAttempts" INTEGER NOT NULL DEFAULT 5,
  "verifiedAt" TIMESTAMP(3),
  "consumedAt" TIMESTAMP(3),
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "AccountDeletionChallenge_pkey" PRIMARY KEY ("id")
);

CREATE TABLE IF NOT EXISTS "AccountDeletionAudit" (
  "id" TEXT NOT NULL,
  "accountId" TEXT NOT NULL,
  "role" "AccountRole" NOT NULL,
  "channel" "AccountDeletionChannel" NOT NULL,
  "status" "AccountDeletionAuditStatus" NOT NULL,
  "requestIp" TEXT,
  "requestUserAgent" TEXT,
  "requestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "deletedAt" TIMESTAMP(3),
  "detailsJson" JSONB,
  "error" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "AccountDeletionAudit_pkey" PRIMARY KEY ("id")
);

CREATE INDEX IF NOT EXISTS "LoginHistory_accountId_createdAt_idx" ON "LoginHistory"("accountId", "createdAt");
CREATE INDEX IF NOT EXISTS "LoginHistory_role_createdAt_idx" ON "LoginHistory"("role", "createdAt");

CREATE INDEX IF NOT EXISTS "AccountDeletionChallenge_accountId_createdAt_idx" ON "AccountDeletionChallenge"("accountId", "createdAt");
CREATE INDEX IF NOT EXISTS "AccountDeletionChallenge_expiresAt_idx" ON "AccountDeletionChallenge"("expiresAt");

CREATE INDEX IF NOT EXISTS "AccountDeletionAudit_accountId_createdAt_idx" ON "AccountDeletionAudit"("accountId", "createdAt");
CREATE INDEX IF NOT EXISTS "AccountDeletionAudit_status_createdAt_idx" ON "AccountDeletionAudit"("status", "createdAt");

DO $$
BEGIN
  ALTER TABLE "LoginHistory"
    ADD CONSTRAINT "LoginHistory_accountId_fkey"
    FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

DO $$
BEGIN
  ALTER TABLE "AccountDeletionChallenge"
    ADD CONSTRAINT "AccountDeletionChallenge_accountId_fkey"
    FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

DO $$
BEGIN
  ALTER TABLE "AccountDeletionAudit"
    ADD CONSTRAINT "AccountDeletionAudit_accountId_fkey"
    FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;
