DO $$
BEGIN
  ALTER TYPE "AccountRole" ADD VALUE IF NOT EXISTS 'EMPLOYER';
EXCEPTION
  WHEN duplicate_object THEN NULL;
END
$$;

ALTER TABLE "Account" ADD COLUMN IF NOT EXISTS "employerId" TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS "Account_employerId_key" ON "Account"("employerId");
