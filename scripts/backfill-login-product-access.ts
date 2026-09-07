import {
  AccountRole,
  OnboardingStatus,
  PrismaClient,
  ProductAccessStatus,
  ProductCode,
  ProductRole,
} from '@prisma/client';

const prisma = new PrismaClient();
const dryRun = !['false', '0', 'no'].includes(
  String(process.env.BACKFILL_DRY_RUN ?? 'true').toLowerCase(),
);
const normalizePatientMember = !['false', '0', 'no'].includes(
  String(process.env.BACKFILL_NORMALIZE_MEMBER ?? 'true').toLowerCase(),
);
const limit = parsePositiveInt(process.env.BACKFILL_LIMIT);
const usersBaseUrl =
  process.env.USERS_BASE_URL?.replace(/\/$/, '') ??
  'http://users-service:3008/usersms';

type RoleTarget = {
  accountRole: AccountRole;
  product: ProductCode;
  productRole: ProductRole;
  subjectId: string;
  doctorId?: string;
  onboardingStatus: OnboardingStatus;
};

const stats = {
  candidates: 0,
  processed: 0,
  profilesCreated: 0,
  profilesUpdated: 0,
  accessesCreated: 0,
  accessesUpdated: 0,
  patientRolesNormalized: 0,
  skippedNoSubject: 0,
  errors: 0,
};

async function main() {
  console.log('=== Login product access backfill ===');
  console.log(JSON.stringify({ dryRun, normalizePatientMember, limit: limit ?? null }, null, 2));

  const accounts = await prisma.account.findMany({
    where: { deletedAt: null },
    include: {
      roleProfiles: true,
      productAccesses: true,
    },
    orderBy: { createdAt: 'asc' },
    ...(limit ? { take: limit } : {}),
  });
  stats.candidates = accounts.length;

  for (const account of accounts) {
    try {
      const targets = await resolveTargets(account);
      const shouldNormalizePatient =
        normalizePatientMember && account.role === AccountRole.PATIENT;
      if (targets.length === 0 && !shouldNormalizePatient) {
        continue;
      }

      stats.processed += 1;
      console.log(
        `[plan] account=${account.id} email=${account.email} ${JSON.stringify({
          targets: targets.map(({ accountRole, product, productRole, subjectId }) => ({
            accountRole,
            product,
            productRole,
            subjectId,
          })),
          normalizePatientMember: shouldNormalizePatient,
        })}`,
      );
      if (dryRun) {
        continue;
      }

      await prisma.$transaction(async (tx) => {
        for (const target of targets) {
          const existingProfile = account.roleProfiles.find(
            (profile) => profile.role === target.accountRole,
          );
          await tx.accountRoleProfile.upsert({
            where: {
              accountId_role: {
                accountId: account.id,
                role: target.accountRole,
              },
            },
            create: {
              accountId: account.id,
              role: target.accountRole,
              subjectId: target.subjectId,
              doctorId: target.doctorId,
              onboardingStatus: target.onboardingStatus,
            },
            update: {
              subjectId: target.subjectId,
              ...(target.doctorId ? { doctorId: target.doctorId } : {}),
            },
          });
          if (existingProfile) stats.profilesUpdated += 1;
          else stats.profilesCreated += 1;

          const existingAccess = account.productAccesses.find(
            (access) =>
              access.product === target.product && access.role === target.productRole,
          );
          await tx.accountProductAccess.upsert({
            where: {
              accountId_product_role: {
                accountId: account.id,
                product: target.product,
                role: target.productRole,
              },
            },
            create: {
              accountId: account.id,
              product: target.product,
              role: target.productRole,
              subjectId: target.subjectId,
              status: ProductAccessStatus.ACTIVE,
            },
            update: {
              subjectId: target.subjectId,
            },
          });
          if (existingAccess) stats.accessesUpdated += 1;
          else stats.accessesCreated += 1;
        }

        if (shouldNormalizePatient) {
          await tx.account.update({
            where: { id: account.id },
            data: { role: AccountRole.MEMBER, subjectId: null },
          });
          stats.patientRolesNormalized += 1;
        }
      });
    } catch (error) {
      stats.errors += 1;
      console.error(
        `[error] account=${account.id} email=${account.email} ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  console.log('=== Summary ===');
  console.log(JSON.stringify(stats, null, 2));
  if (dryRun) {
    console.log('Dry run only. Set BACKFILL_DRY_RUN=false to apply changes.');
  }
}

async function resolveTargets(account: Awaited<ReturnType<typeof loadAccountShape>>) {
  const targets: RoleTarget[] = [];
  const doctorTarget = resolveDoctorTarget(account);
  if (doctorTarget) targets.push(doctorTarget);

  const patientTarget = await resolvePatientTarget(account);
  if (patientTarget) targets.push(patientTarget);

  const employerTarget = await resolveEmployerTarget(account);
  if (employerTarget) targets.push(employerTarget);
  return targets;
}

function loadAccountShape() {
  return prisma.account.findFirstOrThrow({
    include: { roleProfiles: true, productAccesses: true },
  });
}

function resolveDoctorTarget(account: Awaited<ReturnType<typeof loadAccountShape>>): RoleTarget | null {
  const profile = account.roleProfiles.find((entry) => entry.role === AccountRole.DOCTOR);
  const access = account.productAccesses.find(
    (entry) => entry.product === ProductCode.MEUDOC_PRO && entry.role === ProductRole.DOCTOR,
  );
  const hasDoctorSignal =
    account.role === AccountRole.DOCTOR || Boolean(profile) || Boolean(access) || Boolean(account.doctorId);
  if (!hasDoctorSignal) return null;

  const doctorId =
    profile?.doctorId?.trim() ||
    profile?.subjectId?.trim() ||
    access?.subjectId?.trim() ||
    account.doctorId?.trim();
  if (!doctorId) {
    stats.skippedNoSubject += 1;
    return null;
  }
  return {
    accountRole: AccountRole.DOCTOR,
    product: ProductCode.MEUDOC_PRO,
    productRole: ProductRole.DOCTOR,
    subjectId: doctorId,
    doctorId,
    onboardingStatus: profile?.onboardingStatus ?? account.onboardingStatus,
  };
}

async function resolvePatientTarget(
  account: Awaited<ReturnType<typeof loadAccountShape>>,
): Promise<RoleTarget | null> {
  const profile = account.roleProfiles.find((entry) => entry.role === AccountRole.PATIENT);
  const access = account.productAccesses.find(
    (entry) => entry.product === ProductCode.PATIENT_PORTAL && entry.role === ProductRole.PATIENT,
  );
  const hasPatientSignal =
    account.role === AccountRole.PATIENT || Boolean(profile) || Boolean(access);
  if (!hasPatientSignal) return null;

  const patientId =
    pickUuid(profile?.subjectId) ||
    pickUuid(access?.subjectId) ||
    (await lookupPatientIdByAuthUserId(account.id));
  if (!patientId) {
    stats.skippedNoSubject += 1;
    return null;
  }
  return {
    accountRole: AccountRole.PATIENT,
    product: ProductCode.PATIENT_PORTAL,
    productRole: ProductRole.PATIENT,
    subjectId: patientId,
    onboardingStatus: OnboardingStatus.COMPLETE,
  };
}

async function resolveEmployerTarget(
  account: Awaited<ReturnType<typeof loadAccountShape>>,
): Promise<RoleTarget | null> {
  const profile = account.roleProfiles.find((entry) => entry.role === AccountRole.EMPLOYER);
  const access = account.productAccesses.find(
    (entry) =>
      entry.product === ProductCode.MEUDOC_EMPLOYER &&
      (entry.role === ProductRole.EMPLOYER_ADMIN || entry.role === ProductRole.EMPLOYER_BILLING),
  );
  const employerRows = await prisma.$queryRaw<Array<{ employerId: string; productRole: string }>>`
    SELECT "employerId", "productRole"
    FROM "employers"."EmployerMember"
    WHERE "authUserId" = ${account.id}
      AND "status" = CAST('ACTIVE' AS "employers"."EmployerMemberStatus")
    LIMIT 1
  `;
  const employerMember = employerRows[0];
  const hasEmployerSignal =
    account.role === AccountRole.EMPLOYER ||
    Boolean(profile) ||
    Boolean(access) ||
    Boolean(account.employerId) ||
    Boolean(employerMember);
  if (!hasEmployerSignal) return null;

  const employerId =
    profile?.subjectId?.trim() ||
    access?.subjectId?.trim() ||
    account.employerId?.trim() ||
    employerMember?.employerId?.trim();
  if (!employerId) {
    stats.skippedNoSubject += 1;
    return null;
  }
  const productRole =
    access?.role === ProductRole.EMPLOYER_BILLING ||
    employerMember?.productRole === ProductRole.EMPLOYER_BILLING
      ? ProductRole.EMPLOYER_BILLING
      : ProductRole.EMPLOYER_ADMIN;
  return {
    accountRole: AccountRole.EMPLOYER,
    product: ProductCode.MEUDOC_EMPLOYER,
    productRole,
    subjectId: employerId,
    onboardingStatus: profile?.onboardingStatus ?? account.onboardingStatus,
  };
}

async function lookupPatientIdByAuthUserId(authUserId: string) {
  try {
    const response = await fetch(
      `${usersBaseUrl}/patients/internal/by-auth-user/${encodeURIComponent(authUserId)}`,
      { headers: { 'x-role': 'SYSTEM' } },
    );
    if (!response.ok) return null;
    const data = (await response.json()) as { patientId?: string | null };
    return data.patientId?.trim() || null;
  } catch (error) {
    console.warn(
      `[lookup] authUserId=${authUserId} failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
    return null;
  }
}

function parsePositiveInt(value?: string) {
  if (!value?.trim()) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function pickUuid(value?: string | null) {
  const normalized = value?.trim();
  if (!normalized) return null;
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    normalized,
  )
    ? normalized
    : null;
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
