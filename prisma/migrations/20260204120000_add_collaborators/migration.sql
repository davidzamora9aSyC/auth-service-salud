-- AlterEnum
ALTER TYPE "AccountRole" ADD VALUE 'COLLABORATOR';

-- CreateEnum
CREATE TYPE "InviteStatus" AS ENUM ('PENDING', 'ACCEPTED', 'REVOKED', 'EXPIRED');
CREATE TYPE "CollaboratorStatus" AS ENUM ('ACTIVE', 'DISABLED');

-- CreateTable
CREATE TABLE "Permission" (
    "id" TEXT NOT NULL,
    "key" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "description" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Permission_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Collaborator" (
    "id" TEXT NOT NULL,
    "accountId" TEXT NOT NULL,
    "doctorId" TEXT NOT NULL,
    "firstName" TEXT NOT NULL,
    "lastName" TEXT NOT NULL,
    "status" "CollaboratorStatus" NOT NULL DEFAULT 'ACTIVE',
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "Collaborator_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CollaboratorPermission" (
    "collaboratorId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CollaboratorPermission_pkey" PRIMARY KEY ("collaboratorId","permissionId")
);

-- CreateTable
CREATE TABLE "CollaboratorAgenda" (
    "collaboratorId" TEXT NOT NULL,
    "agendaId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CollaboratorAgenda_pkey" PRIMARY KEY ("collaboratorId","agendaId")
);

-- CreateTable
CREATE TABLE "CollaboratorInvite" (
    "id" TEXT NOT NULL,
    "doctorId" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "phoneNumber" TEXT,
    "tokenHash" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "status" "InviteStatus" NOT NULL DEFAULT 'PENDING',
    "inviterAccountId" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CollaboratorInvite_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CollaboratorInvitePermission" (
    "inviteId" TEXT NOT NULL,
    "permissionId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CollaboratorInvitePermission_pkey" PRIMARY KEY ("inviteId","permissionId")
);

-- CreateTable
CREATE TABLE "CollaboratorInviteAgenda" (
    "inviteId" TEXT NOT NULL,
    "agendaId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CollaboratorInviteAgenda_pkey" PRIMARY KEY ("inviteId","agendaId")
);

-- CreateIndex
CREATE UNIQUE INDEX "Permission_key_key" ON "Permission"("key");

-- CreateIndex
CREATE UNIQUE INDEX "Collaborator_accountId_key" ON "Collaborator"("accountId");

-- CreateIndex
CREATE INDEX "Collaborator_doctorId_idx" ON "Collaborator"("doctorId");

-- CreateIndex
CREATE INDEX "CollaboratorPermission_permissionId_idx" ON "CollaboratorPermission"("permissionId");

-- CreateIndex
CREATE INDEX "CollaboratorAgenda_agendaId_idx" ON "CollaboratorAgenda"("agendaId");

-- CreateIndex
CREATE UNIQUE INDEX "CollaboratorInvite_tokenHash_key" ON "CollaboratorInvite"("tokenHash");

-- CreateIndex
CREATE INDEX "CollaboratorInvite_doctorId_idx" ON "CollaboratorInvite"("doctorId");

-- CreateIndex
CREATE INDEX "CollaboratorInvite_email_idx" ON "CollaboratorInvite"("email");

-- CreateIndex
CREATE INDEX "CollaboratorInvitePermission_permissionId_idx" ON "CollaboratorInvitePermission"("permissionId");

-- CreateIndex
CREATE INDEX "CollaboratorInviteAgenda_agendaId_idx" ON "CollaboratorInviteAgenda"("agendaId");

-- AddForeignKey
ALTER TABLE "Collaborator" ADD CONSTRAINT "Collaborator_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "Account"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollaboratorPermission" ADD CONSTRAINT "CollaboratorPermission_collaboratorId_fkey" FOREIGN KEY ("collaboratorId") REFERENCES "Collaborator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollaboratorPermission" ADD CONSTRAINT "CollaboratorPermission_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "Permission"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollaboratorAgenda" ADD CONSTRAINT "CollaboratorAgenda_collaboratorId_fkey" FOREIGN KEY ("collaboratorId") REFERENCES "Collaborator"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollaboratorInvitePermission" ADD CONSTRAINT "CollaboratorInvitePermission_inviteId_fkey" FOREIGN KEY ("inviteId") REFERENCES "CollaboratorInvite"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollaboratorInvitePermission" ADD CONSTRAINT "CollaboratorInvitePermission_permissionId_fkey" FOREIGN KEY ("permissionId") REFERENCES "Permission"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CollaboratorInviteAgenda" ADD CONSTRAINT "CollaboratorInviteAgenda_inviteId_fkey" FOREIGN KEY ("inviteId") REFERENCES "CollaboratorInvite"("id") ON DELETE CASCADE ON UPDATE CASCADE;
