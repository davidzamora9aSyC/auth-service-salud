-- Clinic sessions resolve their business identity from AccountRoleProfile and
-- AccountProductAccess. Preserve Account.role/subjectId as legacy data only.

INSERT INTO "AccountRoleProfile" (
  "id", "accountId", "role", "subjectId", "onboardingStatus", "createdAt", "updatedAt"
)
SELECT
  gen_random_uuid()::text,
  "id",
  'CLINIC'::"AccountRole",
  "subjectId",
  "onboardingStatus",
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM "Account"
WHERE "role" = 'CLINIC'::"AccountRole"
ON CONFLICT ("accountId", "role") DO NOTHING;

INSERT INTO "AccountProductAccess" (
  "id", "accountId", "product", "role", "subjectId", "status", "createdAt", "updatedAt"
)
SELECT
  gen_random_uuid()::text,
  profile."accountId",
  'MEUDOC_PRO'::"ProductCode",
  'MEDICAL_ENTITY'::"ProductRole",
  profile."subjectId",
  'ACTIVE'::"ProductAccessStatus",
  CURRENT_TIMESTAMP,
  CURRENT_TIMESTAMP
FROM "AccountRoleProfile" profile
WHERE profile."role" = 'CLINIC'::"AccountRole"
ON CONFLICT ("accountId", "product", "role")
DO UPDATE SET
  "subjectId" = EXCLUDED."subjectId",
  "updatedAt" = CURRENT_TIMESTAMP
WHERE EXCLUDED."subjectId" IS NOT NULL;
