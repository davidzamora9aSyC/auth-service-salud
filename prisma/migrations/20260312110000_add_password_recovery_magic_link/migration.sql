-- Add magic link fields to password recovery
ALTER TABLE "PasswordRecovery"
  ADD COLUMN "magicTokenHash" TEXT,
  ADD COLUMN "magicExpiresAt" TIMESTAMP(3),
  ADD COLUMN "magicConsumedAt" TIMESTAMP(3);

CREATE INDEX "PasswordRecovery_magicTokenHash_idx" ON "PasswordRecovery"("magicTokenHash");
