-- CreateTable
CREATE TABLE "EmployerInvite" (
    "id" TEXT NOT NULL,
    "employerId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "productRole" "ProductRole" NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "status" "InviteStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "inviterAccountId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "EmployerInvite_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "EmployerInvite_tokenHash_key" ON "EmployerInvite"("tokenHash");

-- CreateIndex
CREATE INDEX "EmployerInvite_employerId_status_idx" ON "EmployerInvite"("employerId", "status");

-- CreateIndex
CREATE INDEX "EmployerInvite_email_idx" ON "EmployerInvite"("email");

-- AddForeignKey
ALTER TABLE "EmployerInvite" ADD CONSTRAINT "EmployerInvite_inviterAccountId_fkey" FOREIGN KEY ("inviterAccountId") REFERENCES "Account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
