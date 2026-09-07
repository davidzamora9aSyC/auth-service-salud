ALTER TABLE "OAuthAuthorizationCode"
  ADD COLUMN IF NOT EXISTS "sessionRole" "AccountRole",
  ADD COLUMN IF NOT EXISTS "activeProduct" "ProductCode",
  ADD COLUMN IF NOT EXISTS "activeProductRole" "ProductRole",
  ADD COLUMN IF NOT EXISTS "productSubjectId" TEXT;
