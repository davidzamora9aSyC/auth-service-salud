import {
  AccountRole,
  PrismaClient,
  ProductAccessStatus,
  ProductCode,
  ProductRole,
} from '@prisma/client';

const prisma = new PrismaClient();

const dryRun = !['false', '0', 'no'].includes(
  String(process.env.BACKFILL_DRY_RUN ?? 'true').toLowerCase(),
);
const normalizeMember = !['false', '0', 'no'].includes(
  String(process.env.BACKFILL_NORMALIZE_MEMBER ?? 'true').toLowerCase(),
);
const limit = parsePositiveInt(process.env.BACKFILL_LIMIT);
const usersBaseUrl =
  process.env.USERS_BASE_URL?.replace(/\/$/, '') ??
  'http://users-service:3008/usersms';

type BackfillStats = {
  candidates: number;
  processed: number;
  roleProfileCreated: number;
  roleProfileUpdated: number;
  productAccessCreated: number;
  productAccessUpdated: number;
  accountRoleNormalized: number;
  skippedNoPatientId: number;
  skippedDeleted: number;
  skippedComplete: number;
  errors: number;
};

async function main() {
  const stats: BackfillStats = {
    candidates: 0,
    processed: 0,
    roleProfileCreated: 0,
    roleProfileUpdated: 0,
    productAccessCreated: 0,
    productAccessUpdated: 0,
    accountRoleNormalized: 0,
    skippedNoPatientId: 0,
    skippedDeleted: 0,
    skippedComplete: 0,
    errors: 0,
  };

  console.log('=== Patient product access backfill ===');
  console.log(
    JSON.stringify(
      {
        dryRun,
        normalizeMember,
        limit: limit ?? null,
        usersBaseUrl,
      },
      null,
      2,
    ),
  );

  const accounts = await prisma.account.findMany({
    where: {
      deletedAt: null,
      OR: [
        { role: AccountRole.PATIENT },
        { roleProfiles: { some: { role: AccountRole.PATIENT } } },
        {
          productAccesses: {
            some: {
              product: ProductCode.PATIENT_PORTAL,
              role: ProductRole.PATIENT,
            },
          },
        },
      ],
    },
    include: {
      roleProfiles: true,
      productAccesses: true,
    },
    orderBy: { createdAt: 'asc' },
    ...(limit ? { take: limit } : {}),
  });

  stats.candidates = accounts.length;

  for (const account of accounts) {
    if (account.deletedAt) {
      stats.skippedDeleted += 1;
      continue;
    }

    const patientProfile = account.roleProfiles.find(
      (profile) => profile.role === AccountRole.PATIENT,
    );
    const patientProductAccess = account.productAccesses.find(
      (access) =>
        access.product === ProductCode.PATIENT_PORTAL &&
        access.role === ProductRole.PATIENT,
    );

    const needsRoleProfile =
      !patientProfile || !patientProfile.subjectId?.trim();
    const needsProductAccess = !patientProductAccess;
    const needsProductSubjectId =
      Boolean(patientProductAccess) && !patientProductAccess?.subjectId?.trim();
    const needsRoleNormalization =
      normalizeMember && account.role === AccountRole.PATIENT;

    if (
      !needsRoleProfile &&
      !needsProductAccess &&
      !needsProductSubjectId &&
      !needsRoleNormalization
    ) {
      stats.skippedComplete += 1;
      continue;
    }

    try {
      const patientId = await resolvePatientId(account.id, account, patientProfile);
      if (!patientId) {
        stats.skippedNoPatientId += 1;
        console.warn(
          `[skip] account=${account.id} email=${account.email} reason=no_patient_id`,
        );
        continue;
      }

      stats.processed += 1;
      logPlannedChanges(account.id, account.email, {
        patientId,
        needsRoleProfile,
        needsProductAccess,
        needsProductSubjectId,
        needsRoleNormalization,
        currentRole: account.role,
        productAccessStatus: patientProductAccess?.status ?? null,
      });

      if (dryRun) {
        continue;
      }

      if (needsRoleProfile || needsProductSubjectId) {
        const existingProfile = patientProfile;
        await prisma.accountRoleProfile.upsert({
          where: {
            accountId_role: {
              accountId: account.id,
              role: AccountRole.PATIENT,
            },
          },
          create: {
            accountId: account.id,
            role: AccountRole.PATIENT,
            subjectId: patientId,
          },
          update: {
            subjectId: patientId,
          },
        });
        if (existingProfile) {
          stats.roleProfileUpdated += 1;
        } else {
          stats.roleProfileCreated += 1;
        }
      }

      if (needsProductAccess || needsProductSubjectId) {
        const existingAccess = patientProductAccess;
        await prisma.accountProductAccess.upsert({
          where: {
            accountId_product_role: {
              accountId: account.id,
              product: ProductCode.PATIENT_PORTAL,
              role: ProductRole.PATIENT,
            },
          },
          create: {
            accountId: account.id,
            product: ProductCode.PATIENT_PORTAL,
            role: ProductRole.PATIENT,
            subjectId: patientId,
            status: ProductAccessStatus.ACTIVE,
          },
          update: {
            subjectId: patientId,
          },
        });
        if (existingAccess) {
          stats.productAccessUpdated += 1;
        } else {
          stats.productAccessCreated += 1;
        }
      }

      if (needsRoleNormalization) {
        await prisma.account.update({
          where: { id: account.id },
          data: {
            role: AccountRole.MEMBER,
            subjectId: null,
          },
        });
        stats.accountRoleNormalized += 1;
      }
    } catch (error) {
      stats.errors += 1;
      const message = error instanceof Error ? error.message : String(error);
      console.error(`[error] account=${account.id} email=${account.email} ${message}`);
    }
  }

  console.log('=== Summary ===');
  console.log(JSON.stringify(stats, null, 2));

  if (dryRun) {
    console.log('Dry run only. Set BACKFILL_DRY_RUN=false to apply changes.');
  }
}

async function resolvePatientId(
  accountId: string,
  account: {
    role: AccountRole;
    subjectId: string | null;
  },
  patientProfile?: { subjectId: string | null } | null,
) {
  const profileSubjectId = patientProfile?.subjectId?.trim();
  if (profileSubjectId && isUuid(profileSubjectId)) {
    return profileSubjectId;
  }

  return lookupPatientIdByAuthUserId(accountId);
}

async function lookupPatientIdByAuthUserId(authUserId: string) {
  try {
    const response = await fetch(
      `${usersBaseUrl}/patients/internal/by-auth-user/${encodeURIComponent(authUserId)}`,
      {
        headers: {
          'x-role': 'SYSTEM',
        },
      },
    );
    if (!response.ok) {
      return null;
    }
    const data = (await response.json()) as { patientId?: string | null };
    return data.patientId?.trim() || null;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.warn(`[lookup] authUserId=${authUserId} failed: ${message}`);
    return null;
  }
}

function logPlannedChanges(
  accountId: string,
  email: string,
  details: Record<string, unknown>,
) {
  console.log(
    `[plan] account=${accountId} email=${email} ${JSON.stringify(details)}`,
  );
}

function parsePositiveInt(value?: string) {
  if (!value?.trim()) {
    return undefined;
  }
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value,
  );
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
