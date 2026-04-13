ALTER TYPE "TwoFactorMethod" ADD VALUE IF NOT EXISTS 'WHATSAPP';

DO $$
BEGIN
  CREATE TYPE "TwoFactorChallengePurpose" AS ENUM ('LOGIN', 'SETUP', 'DISABLE');
EXCEPTION
  WHEN duplicate_object THEN NULL;
END $$;

ALTER TABLE "Account"
  ADD COLUMN IF NOT EXISTS "twoFactorMethod" "TwoFactorMethod";

UPDATE "Account"
SET "twoFactorMethod" = 'TOTP'
WHERE "twoFactorEnabled" = TRUE
  AND "twoFactorMethod" IS NULL;

ALTER TABLE "TwoFactorChallenge"
  ADD COLUMN IF NOT EXISTS "purpose" "TwoFactorChallengePurpose" NOT NULL DEFAULT 'LOGIN',
  ADD COLUMN IF NOT EXISTS "codeHash" TEXT,
  ADD COLUMN IF NOT EXISTS "destination" TEXT;
