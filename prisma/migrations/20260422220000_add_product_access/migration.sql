ALTER TYPE "AccountRole" ADD VALUE IF NOT EXISTS 'MEMBER';

CREATE TYPE "ProductCode" AS ENUM ('MEUDOC_PRO', 'PATIENT_PORTAL', 'MEUDOC_ADMIN', 'MEURED');
CREATE TYPE "ProductRole" AS ENUM ('DOCTOR', 'RESEARCHER', 'STUDENT', 'MEDICAL_ENTITY', 'ENTITY_ADMIN', 'ADMIN');
CREATE TYPE "ProductAccessStatus" AS ENUM ('ACTIVE', 'PENDING', 'SUSPENDED', 'DISABLED');

CREATE TABLE "AccountProductAccess" (
  "id" TEXT NOT NULL,
  "accountId" TEXT NOT NULL,
  "product" "ProductCode" NOT NULL,
  "role" "ProductRole" NOT NULL,
  "subjectId" TEXT,
  "status" "ProductAccessStatus" NOT NULL DEFAULT 'ACTIVE',
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" TIMESTAMP(3) NOT NULL,

  CONSTRAINT "AccountProductAccess_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "AccountProductAccess_accountId_product_role_key" ON "AccountProductAccess"("accountId", "product", "role");
CREATE INDEX "AccountProductAccess_accountId_idx" ON "AccountProductAccess"("accountId");
CREATE INDEX "AccountProductAccess_product_role_idx" ON "AccountProductAccess"("product", "role");
CREATE INDEX "AccountProductAccess_subjectId_idx" ON "AccountProductAccess"("subjectId");

ALTER TABLE "AccountProductAccess"
  ADD CONSTRAINT "AccountProductAccess_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "RefreshToken"
  ADD COLUMN "activeProduct" "ProductCode",
  ADD COLUMN "activeProductRole" "ProductRole",
  ADD COLUMN "productSubjectId" TEXT;

INSERT INTO "AccountProductAccess" ("id", "accountId", "product", "role", "subjectId", "status", "updatedAt")
SELECT gen_random_uuid()::text, "id", 'MEUDOC_PRO', 'DOCTOR', "doctorId", 'ACTIVE', CURRENT_TIMESTAMP
FROM "Account"
WHERE "role" = 'DOCTOR'
  AND "doctorId" IS NOT NULL
ON CONFLICT ("accountId", "product", "role") DO NOTHING;

INSERT INTO "AccountProductAccess" ("id", "accountId", "product", "role", "subjectId", "status", "updatedAt")
SELECT gen_random_uuid()::text, "id", 'MEUDOC_PRO', 'MEDICAL_ENTITY', "subjectId", 'ACTIVE', CURRENT_TIMESTAMP
FROM "Account"
WHERE "role" = 'CLINIC'
  AND "subjectId" IS NOT NULL
ON CONFLICT ("accountId", "product", "role") DO NOTHING;

INSERT INTO "AccountProductAccess" ("id", "accountId", "product", "role", "subjectId", "status", "updatedAt")
SELECT gen_random_uuid()::text, "id", 'MEUDOC_ADMIN', 'ADMIN', NULL, 'ACTIVE', CURRENT_TIMESTAMP
FROM "Account"
WHERE "role" = 'ADMIN'
ON CONFLICT ("accountId", "product", "role") DO NOTHING;
