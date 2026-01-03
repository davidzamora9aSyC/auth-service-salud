-- CreateEnum
CREATE TYPE "OnboardingStatus" AS ENUM ('PENDING', 'COMPLETE');

-- AlterTable
ALTER TABLE "Account" ADD COLUMN "doctorId" TEXT;
ALTER TABLE "Account" ADD COLUMN "onboardingStatus" "OnboardingStatus" NOT NULL DEFAULT 'COMPLETE';

-- CreateIndex
CREATE UNIQUE INDEX "Account_doctorId_key" ON "Account"("doctorId");
