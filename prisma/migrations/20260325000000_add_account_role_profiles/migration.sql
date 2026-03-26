-- CreateTable
CREATE TABLE "AccountRoleProfile" (
    "id" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "role" "AccountRole" NOT NULL,
    "subjectId" TEXT,
    "doctorId" TEXT,
    "onboardingStatus" "OnboardingStatus" NOT NULL DEFAULT 'COMPLETE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "AccountRoleProfile_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "AccountRoleProfile_doctorId_key" ON "AccountRoleProfile"("doctorId");

-- CreateIndex
CREATE UNIQUE INDEX "AccountRoleProfile_accountId_role_key" ON "AccountRoleProfile"("accountId", "role");

-- CreateIndex
CREATE INDEX "AccountRoleProfile_accountId_idx" ON "AccountRoleProfile"("accountId");

-- AddForeignKey
ALTER TABLE "AccountRoleProfile" ADD CONSTRAINT "AccountRoleProfile_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;
