ALTER TABLE "TwoFactorChallenge"
  ADD COLUMN IF NOT EXISTS "activeProduct" "ProductCode",
  ADD COLUMN IF NOT EXISTS "activeProductRole" "ProductRole",
  ADD COLUMN IF NOT EXISTS "productSubjectId" TEXT;
