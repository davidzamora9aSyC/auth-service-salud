-- CreateEnum
CREATE TYPE "ClinicAdminRole" AS ENUM ('OWNER', 'ADMIN');

-- CreateEnum
CREATE TYPE "ClinicDoctorMembershipStatus" AS ENUM ('ACTIVE', 'REMOVED');

-- CreateTable
CREATE TABLE "Clinic" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "legalName" TEXT,
    "taxId" TEXT,
    "description" TEXT,
    "website" TEXT,
    "phoneNumber" TEXT,
    "email" TEXT,
    "profileImageId" TEXT,
    "coverImageId" TEXT,
    "createdByAccountId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Clinic_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClinicAdmin" (
    "clinicId" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "role" "ClinicAdminRole" NOT NULL DEFAULT 'ADMIN',
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClinicAdmin_pkey" PRIMARY KEY ("clinicId","accountId")
);

-- CreateTable
CREATE TABLE "ClinicDoctorMembership" (
    "clinicId" TEXT NOT NULL,
    "doctorId" TEXT NOT NULL,
    "status" "ClinicDoctorMembershipStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdByAccountId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClinicDoctorMembership_pkey" PRIMARY KEY ("clinicId","doctorId")
);

-- CreateTable
CREATE TABLE "ClinicDoctorInvite" (
    "id" TEXT NOT NULL,
    "clinicId" TEXT NOT NULL,
    "doctorId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "tokenHash" TEXT NOT NULL,
    "status" "InviteStatus" NOT NULL DEFAULT 'PENDING',
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "inviterAccountId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClinicDoctorInvite_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "Clinic_name_idx" ON "Clinic"("name");

-- CreateIndex
CREATE INDEX "Clinic_createdByAccountId_idx" ON "Clinic"("createdByAccountId");

-- CreateIndex
CREATE INDEX "ClinicAdmin_accountId_idx" ON "ClinicAdmin"("accountId");

-- CreateIndex
CREATE INDEX "ClinicAdmin_active_idx" ON "ClinicAdmin"("active");

-- CreateIndex
CREATE INDEX "ClinicDoctorMembership_doctorId_idx" ON "ClinicDoctorMembership"("doctorId");

-- CreateIndex
CREATE INDEX "ClinicDoctorMembership_status_idx" ON "ClinicDoctorMembership"("status");

-- CreateIndex
CREATE INDEX "ClinicDoctorMembership_createdByAccountId_idx" ON "ClinicDoctorMembership"("createdByAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "ClinicDoctorInvite_tokenHash_key" ON "ClinicDoctorInvite"("tokenHash");

-- CreateIndex
CREATE INDEX "ClinicDoctorInvite_clinicId_status_idx" ON "ClinicDoctorInvite"("clinicId", "status");

-- CreateIndex
CREATE INDEX "ClinicDoctorInvite_doctorId_status_idx" ON "ClinicDoctorInvite"("doctorId", "status");

-- CreateIndex
CREATE INDEX "ClinicDoctorInvite_email_idx" ON "ClinicDoctorInvite"("email");

-- AddForeignKey
ALTER TABLE "Clinic" ADD CONSTRAINT "Clinic_createdByAccountId_fkey" FOREIGN KEY ("createdByAccountId") REFERENCES "Account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicAdmin" ADD CONSTRAINT "ClinicAdmin_clinicId_fkey" FOREIGN KEY ("clinicId") REFERENCES "Clinic"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicAdmin" ADD CONSTRAINT "ClinicAdmin_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicDoctorMembership" ADD CONSTRAINT "ClinicDoctorMembership_createdByAccountId_fkey" FOREIGN KEY ("createdByAccountId") REFERENCES "Account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicDoctorMembership" ADD CONSTRAINT "ClinicDoctorMembership_clinicId_fkey" FOREIGN KEY ("clinicId") REFERENCES "Clinic"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicDoctorInvite" ADD CONSTRAINT "ClinicDoctorInvite_inviterAccountId_fkey" FOREIGN KEY ("inviterAccountId") REFERENCES "Account"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicDoctorInvite" ADD CONSTRAINT "ClinicDoctorInvite_clinicId_fkey" FOREIGN KEY ("clinicId") REFERENCES "Clinic"("id") ON DELETE CASCADE ON UPDATE CASCADE;
