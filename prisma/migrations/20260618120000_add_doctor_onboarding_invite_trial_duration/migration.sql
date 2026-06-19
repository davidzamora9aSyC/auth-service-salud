-- CreateEnum
CREATE TYPE "TrialDurationUnit" AS ENUM ('DAY', 'MONTH');

-- AlterTable
ALTER TABLE "DoctorOnboardingInvite"
ADD COLUMN "trialDurationValue" INTEGER,
ADD COLUMN "trialDurationUnit" "TrialDurationUnit";
