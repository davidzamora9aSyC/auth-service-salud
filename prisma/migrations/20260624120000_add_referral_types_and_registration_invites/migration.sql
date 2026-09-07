CREATE TYPE "ReferralType" AS ENUM ('DOCTOR', 'PATIENT', 'COMPANY');

ALTER TABLE "DoctorReferral"
  ADD COLUMN "referralType" "ReferralType" NOT NULL DEFAULT 'DOCTOR',
  ADD COLUMN "companyName" TEXT,
  ADD COLUMN "taxId" TEXT,
  ADD COLUMN "patientId" TEXT,
  ADD COLUMN "employerId" TEXT;

CREATE TABLE "ReferralRegistrationInvite" (
  "id" TEXT NOT NULL,
  "referralId" TEXT,
  "type" "ReferralType" NOT NULL,
  "email" TEXT NOT NULL,
  "phoneNumber" TEXT NOT NULL,
  "firstName" TEXT NOT NULL,
  "lastName" TEXT NOT NULL,
  "companyName" TEXT,
  "taxId" TEXT,
  "tokenHash" TEXT NOT NULL,
  "status" "InviteStatus" NOT NULL DEFAULT 'PENDING',
  "expiresAt" TIMESTAMP(3) NOT NULL,
  "createdByUserId" TEXT,
  "acceptedAuthUserId" TEXT,
  "acceptedSubjectId" TEXT,
  "lastSentAt" TIMESTAMP(3),
  "lastSentChannel" TEXT,
  "sentCount" INTEGER NOT NULL DEFAULT 0,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "ReferralRegistrationInvite_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ReferralRegistrationInvite_referralId_key" ON "ReferralRegistrationInvite"("referralId");
CREATE UNIQUE INDEX "ReferralRegistrationInvite_tokenHash_key" ON "ReferralRegistrationInvite"("tokenHash");
CREATE INDEX "DoctorReferral_salesRepId_referralType_status_idx" ON "DoctorReferral"("salesRepId", "referralType", "status");
CREATE INDEX "DoctorReferral_email_idx" ON "DoctorReferral"("email");
CREATE INDEX "ReferralRegistrationInvite_type_status_idx" ON "ReferralRegistrationInvite"("type", "status");
CREATE INDEX "ReferralRegistrationInvite_email_idx" ON "ReferralRegistrationInvite"("email");
CREATE INDEX "ReferralRegistrationInvite_phoneNumber_idx" ON "ReferralRegistrationInvite"("phoneNumber");
CREATE INDEX "ReferralRegistrationInvite_createdByUserId_idx" ON "ReferralRegistrationInvite"("createdByUserId");

ALTER TABLE "ReferralRegistrationInvite"
  ADD CONSTRAINT "ReferralRegistrationInvite_referralId_fkey"
  FOREIGN KEY ("referralId") REFERENCES "DoctorReferral"("id") ON DELETE CASCADE ON UPDATE CASCADE;
