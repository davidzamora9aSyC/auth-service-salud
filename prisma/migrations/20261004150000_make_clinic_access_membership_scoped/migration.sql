-- A clinic relationship is now owned by clinics-service. Auth keeps only the
-- generic entitlement to the clinic portal; the active clinic is session data.
UPDATE "AccountRoleProfile"
SET "subjectId" = NULL
WHERE "role" = 'CLINIC'::"AccountRole";

UPDATE "AccountProductAccess"
SET "subjectId" = NULL
WHERE "product" = 'MEUDOC_PRO'::"ProductCode"
  AND "role" = 'MEDICAL_ENTITY'::"ProductRole";
