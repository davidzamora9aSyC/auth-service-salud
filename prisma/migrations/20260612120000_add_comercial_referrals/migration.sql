DO $$
BEGIN
  ALTER TYPE "AccountRole" ADD VALUE IF NOT EXISTS 'COMERCIAL';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

DO $$
BEGIN
  ALTER TYPE "ProductRole" ADD VALUE IF NOT EXISTS 'COMERCIAL';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

CREATE TYPE "DoctorReferralStatus" AS ENUM (
  'NEW',
  'IN_CONTACT',
  'INTERESTED',
  'ONBOARDING_SENT',
  'ACCOUNT_CREATED',
  'ACTIVE',
  'LOST',
  'DUPLICATE'
);

CREATE TABLE "DoctorReferral" (
  "id" TEXT NOT NULL,
  "salesRepId" TEXT NOT NULL,
  "fullName" TEXT NOT NULL,
  "phoneNumber" TEXT NOT NULL,
  "email" TEXT,
  "status" "DoctorReferralStatus" NOT NULL DEFAULT 'NEW',
  "statusNote" TEXT,
  "doctorId" TEXT,
  "onboardingInviteId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "DoctorReferral_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "DoctorReferral_doctorId_key" ON "DoctorReferral"("doctorId");
CREATE INDEX "DoctorReferral_salesRepId_status_idx" ON "DoctorReferral"("salesRepId", "status");
CREATE INDEX "DoctorReferral_phoneNumber_idx" ON "DoctorReferral"("phoneNumber");
CREATE INDEX "DoctorReferral_fullName_idx" ON "DoctorReferral"("fullName");
CREATE INDEX "DoctorReferral_createdAt_idx" ON "DoctorReferral"("createdAt");

ALTER TABLE "DoctorReferral"
  ADD CONSTRAINT "DoctorReferral_salesRepId_fkey"
  FOREIGN KEY ("salesRepId") REFERENCES "Account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "DoctorOnboardingInvite" ADD COLUMN IF NOT EXISTS "createdByUserId" TEXT;
CREATE INDEX IF NOT EXISTS "DoctorOnboardingInvite_createdByUserId_idx" ON "DoctorOnboardingInvite"("createdByUserId");
