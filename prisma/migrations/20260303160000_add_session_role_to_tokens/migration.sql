ALTER TABLE "RefreshToken"
ADD COLUMN IF NOT EXISTS "sessionRole" "AccountRole",
ADD COLUMN IF NOT EXISTS "sessionSubjectId" TEXT;

ALTER TABLE "TwoFactorChallenge"
ADD COLUMN IF NOT EXISTS "sessionRole" "AccountRole";
