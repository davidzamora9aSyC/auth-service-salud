CREATE TABLE IF NOT EXISTS "AccountIdentityReuseAudit" (
  "id" TEXT NOT NULL DEFAULT uuid(),
  "accountId" TEXT NOT NULL,
  "previousAccountId" TEXT,
  "previousDeletionAuditId" TEXT,
  "matchedBy" TEXT NOT NULL,
  "matchedValue" TEXT,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT "AccountIdentityReuseAudit_pkey" PRIMARY KEY ("id"),
  CONSTRAINT "AccountIdentityReuseAudit_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE
);

CREATE INDEX IF NOT EXISTS "AccountIdentityReuseAudit_accountId_createdAt_idx" ON "AccountIdentityReuseAudit"("accountId", "createdAt");
CREATE INDEX IF NOT EXISTS "AccountIdentityReuseAudit_previousAccountId_createdAt_idx" ON "AccountIdentityReuseAudit"("previousAccountId", "createdAt");
CREATE INDEX IF NOT EXISTS "AccountIdentityReuseAudit_matchedBy_createdAt_idx" ON "AccountIdentityReuseAudit"("matchedBy", "createdAt");
