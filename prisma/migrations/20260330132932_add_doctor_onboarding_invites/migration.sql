-- AlterTable
ALTER TABLE "AccountPhoneChange" ALTER COLUMN "id" DROP DEFAULT;

-- CreateTable
CREATE TABLE "DoctorOnboardingInvite" (
    "id" TEXT NOT NULL,
    "doctorId" TEXT NOT NULL,
    "authUserId" TEXT,
    "email" TEXT NOT NULL,
    "phoneNumber" TEXT,
    "firstName" TEXT,
    "lastName" TEXT,
    "tokenHash" TEXT NOT NULL,
    "status" "InviteStatus" NOT NULL DEFAULT 'PENDING',
    "preferredPlanCode" TEXT,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "DoctorOnboardingInvite_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "DoctorOnboardingInvite_doctorId_key" ON "DoctorOnboardingInvite"("doctorId");

-- CreateIndex
CREATE UNIQUE INDEX "DoctorOnboardingInvite_tokenHash_key" ON "DoctorOnboardingInvite"("tokenHash");

-- CreateIndex
CREATE INDEX "DoctorOnboardingInvite_email_idx" ON "DoctorOnboardingInvite"("email");

-- CreateIndex
CREATE INDEX "DoctorOnboardingInvite_doctorId_status_idx" ON "DoctorOnboardingInvite"("doctorId", "status");
