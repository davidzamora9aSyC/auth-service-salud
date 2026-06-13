DO $$
BEGIN
  ALTER TYPE "DoctorReferralStatus" ADD VALUE IF NOT EXISTS 'PAYING_PLAN';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

ALTER TABLE "DoctorReferral" ADD COLUMN IF NOT EXISTS "subscriptionPlanCode" TEXT;
