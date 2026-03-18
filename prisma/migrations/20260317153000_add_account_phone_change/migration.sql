-- CreateEnum
CREATE TYPE "AccountVerificationChannel" AS ENUM ('EMAIL', 'WHATSAPP');

-- CreateTable
CREATE TABLE "AccountPhoneChange" (
    "id" TEXT NOT NULL DEFAULT gen_random_uuid()::text,
    "accountId" TEXT NOT NULL,
    "channel" "AccountVerificationChannel" NOT NULL,
    "destination" TEXT NOT NULL,
    "codeHash" TEXT NOT NULL,
    "tokenHash" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "tokenExpiresAt" TIMESTAMP(3),
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "maxAttempts" INTEGER NOT NULL DEFAULT 5,
    "verifiedAt" TIMESTAMP(3),
    "consumedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "AccountPhoneChange_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AccountPhoneChange_accountId_createdAt_idx" ON "AccountPhoneChange"("accountId", "createdAt");
CREATE INDEX "AccountPhoneChange_expiresAt_idx" ON "AccountPhoneChange"("expiresAt");

-- AddForeignKey
ALTER TABLE "AccountPhoneChange" ADD CONSTRAINT "AccountPhoneChange_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;
