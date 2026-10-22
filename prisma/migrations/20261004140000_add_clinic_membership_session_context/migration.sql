ALTER TABLE "RefreshToken"
  ADD COLUMN "clinicMembershipId" TEXT,
  ADD COLUMN "clinicMembershipRole" TEXT,
  ADD COLUMN "clinicPermissions" TEXT[] NOT NULL DEFAULT ARRAY[]::TEXT[];
