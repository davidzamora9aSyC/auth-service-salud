-- CreateTable
CREATE TABLE "ClinicLocation" (
    "id" TEXT NOT NULL,
    "clinicId" TEXT NOT NULL,
    "label" TEXT,
    "city" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "postalCode" TEXT,
    "additionalInfo" TEXT,
    "placeId" TEXT,
    "formattedAddress" TEXT,
    "department" TEXT,
    "countryCode" TEXT,
    "lat" DOUBLE PRECISION,
    "lng" DOUBLE PRECISION,
    "isPrimary" BOOLEAN NOT NULL DEFAULT false,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdByAccountId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClinicLocation_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ClinicAgendaAssignment" (
    "clinicLocationId" TEXT NOT NULL,
    "agendaId" TEXT NOT NULL,
    "doctorId" TEXT NOT NULL,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "createdByAccountId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ClinicAgendaAssignment_pkey" PRIMARY KEY ("clinicLocationId","agendaId")
);

-- CreateIndex
CREATE INDEX "ClinicLocation_clinicId_active_idx" ON "ClinicLocation"("clinicId", "active");

-- CreateIndex
CREATE INDEX "ClinicLocation_clinicId_isPrimary_idx" ON "ClinicLocation"("clinicId", "isPrimary");

-- CreateIndex
CREATE INDEX "ClinicLocation_createdByAccountId_idx" ON "ClinicLocation"("createdByAccountId");

-- CreateIndex
CREATE INDEX "ClinicAgendaAssignment_doctorId_active_idx" ON "ClinicAgendaAssignment"("doctorId", "active");

-- CreateIndex
CREATE INDEX "ClinicAgendaAssignment_createdByAccountId_idx" ON "ClinicAgendaAssignment"("createdByAccountId");

-- CreateIndex
CREATE UNIQUE INDEX "ClinicAgendaAssignment_agendaId_key" ON "ClinicAgendaAssignment"("agendaId");

-- AddForeignKey
ALTER TABLE "ClinicLocation" ADD CONSTRAINT "ClinicLocation_clinicId_fkey" FOREIGN KEY ("clinicId") REFERENCES "Clinic"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ClinicAgendaAssignment" ADD CONSTRAINT "ClinicAgendaAssignment_clinicLocationId_fkey" FOREIGN KEY ("clinicLocationId") REFERENCES "ClinicLocation"("id") ON DELETE CASCADE ON UPDATE CASCADE;
