CREATE TABLE "DoctorOnboardingSettings" (
  "id" TEXT NOT NULL DEFAULT 'default',
  "inviteTrialDurationValue" INTEGER NOT NULL DEFAULT 1,
  "inviteTrialDurationUnit" "TrialDurationUnit" NOT NULL DEFAULT 'MONTH',
  "updatedByUserId" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,
  CONSTRAINT "DoctorOnboardingSettings_pkey" PRIMARY KEY ("id")
);
