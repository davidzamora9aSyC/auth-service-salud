import { PrismaClient } from '@prisma/client';
import { writeFileSync } from 'node:fs';

const prisma = new PrismaClient();

const accountIdFilter = process.env.AUDIT_ACCOUNT_ID?.trim() || null;
const emailFilter = process.env.AUDIT_EMAIL?.trim().toLowerCase() || null;
const outputFile = process.env.AUDIT_OUTPUT_FILE?.trim() || null;
const exampleLimit = parsePositiveInt(process.env.AUDIT_EXAMPLE_LIMIT) ?? 5;

type PatientRow = {
  accountId: string;
  email: string;
  accountRole: string;
  accountSubjectId: string | null;
  patientProfileSubjectId: string | null;
  patientAccessSubjectId: string | null;
  patientByAuthId: string | null;
  patientByProfileId: string | null;
  patientByAccessId: string | null;
};

type DoctorRow = {
  accountId: string;
  email: string;
  accountRole: string;
  accountDoctorId: string | null;
  doctorProfileSubjectId: string | null;
  doctorProfileDoctorId: string | null;
  doctorAccessSubjectId: string | null;
  doctorByAuthId: string | null;
  doctorByAccountDoctorId: string | null;
  doctorByProfileId: string | null;
  doctorByAccessId: string | null;
};

type AuditCase = {
  type: string;
  severity: 'high' | 'medium';
  accountId: string;
  email: string;
  details: Record<string, string | null>;
};

async function main() {
  console.log('=== Account Link Integrity Audit (read-only) ===');
  console.log(
    JSON.stringify(
      {
        accountIdFilter,
        emailFilter,
        outputFile,
        exampleLimit,
      },
      null,
      2,
    ),
  );

  const [patientRows, doctorRows] = await Promise.all([
    loadPatientRows(),
    loadDoctorRows(),
  ]);

  const cases = [
    ...patientRows.flatMap(classifyPatientRow),
    ...doctorRows.flatMap(classifyDoctorRow),
  ].filter(matchesFilters);

  const summary = summarize(cases);
  const report = {
    generatedAt: new Date().toISOString(),
    filters: { accountIdFilter, emailFilter, exampleLimit },
    totals: {
      patientCandidates: patientRows.filter(matchesRowFilter).length,
      doctorCandidates: doctorRows.filter(matchesRowFilter).length,
      cases: cases.length,
      affectedAccounts: new Set(cases.map((item) => item.accountId)).size,
    },
    summary,
    cases,
  };

  console.log('--- Summary ---');
  console.log(JSON.stringify(report.totals, null, 2));
  for (const item of summary) {
    console.log(
      `${item.type}: count=${item.count} severity=${item.severity} affectedAccounts=${item.affectedAccounts}`,
    );
    for (const example of item.examples) {
      console.log(
        `  - accountId=${example.accountId} email=${example.email} details=${JSON.stringify(example.details)}`,
      );
    }
  }

  if (outputFile) {
    writeFileSync(outputFile, JSON.stringify(report, null, 2), 'utf8');
    console.log(`Wrote JSON report to ${outputFile}`);
  }
}

async function loadPatientRows() {
  return prisma.$queryRaw<PatientRow[]>`
    SELECT
      a.id AS "accountId",
      a.email AS "email",
      a.role::text AS "accountRole",
      a."subjectId" AS "accountSubjectId",
      rp."subjectId" AS "patientProfileSubjectId",
      apa."subjectId" AS "patientAccessSubjectId",
      p_auth.id AS "patientByAuthId",
      p_profile.id AS "patientByProfileId",
      p_access.id AS "patientByAccessId"
    FROM "Account" a
    LEFT JOIN "AccountRoleProfile" rp
      ON rp."accountId" = a.id
      AND rp.role::text = 'PATIENT'
    LEFT JOIN "AccountProductAccess" apa
      ON apa."accountId" = a.id
      AND apa.product::text = 'PATIENT_PORTAL'
      AND apa.role::text = 'PATIENT'
      AND apa.status::text = 'ACTIVE'
    LEFT JOIN "users"."Patient" p_auth
      ON p_auth."authUserId" = a.id
    LEFT JOIN "users"."Patient" p_profile
      ON p_profile.id = rp."subjectId"
    LEFT JOIN "users"."Patient" p_access
      ON p_access.id = apa."subjectId"
    WHERE a."deletedAt" IS NULL
      AND (
        a.role::text = 'PATIENT'
        OR rp.id IS NOT NULL
        OR apa.id IS NOT NULL
      )
    ORDER BY a."createdAt" DESC
  `;
}

async function loadDoctorRows() {
  return prisma.$queryRaw<DoctorRow[]>`
    SELECT
      a.id AS "accountId",
      a.email AS "email",
      a.role::text AS "accountRole",
      a."doctorId" AS "accountDoctorId",
      rp."subjectId" AS "doctorProfileSubjectId",
      rp."doctorId" AS "doctorProfileDoctorId",
      apa."subjectId" AS "doctorAccessSubjectId",
      d_auth.id AS "doctorByAuthId",
      d_account.id AS "doctorByAccountDoctorId",
      d_profile.id AS "doctorByProfileId",
      d_access.id AS "doctorByAccessId"
    FROM "Account" a
    LEFT JOIN "AccountRoleProfile" rp
      ON rp."accountId" = a.id
      AND rp.role::text = 'DOCTOR'
    LEFT JOIN "AccountProductAccess" apa
      ON apa."accountId" = a.id
      AND apa.product::text = 'MEUDOC_PRO'
      AND apa.role::text = 'DOCTOR'
      AND apa.status::text = 'ACTIVE'
    LEFT JOIN "doctors"."Doctor" d_auth
      ON d_auth."authUserId" = a.id
    LEFT JOIN "doctors"."Doctor" d_account
      ON d_account.id = a."doctorId"
    LEFT JOIN "doctors"."Doctor" d_profile
      ON d_profile.id = COALESCE(rp."doctorId", rp."subjectId")
    LEFT JOIN "doctors"."Doctor" d_access
      ON d_access.id = apa."subjectId"
    WHERE a."deletedAt" IS NULL
      AND (
        a.role::text = 'DOCTOR'
        OR a."doctorId" IS NOT NULL
        OR rp.id IS NOT NULL
        OR apa.id IS NOT NULL
      )
    ORDER BY a."createdAt" DESC
  `;
}

function classifyPatientRow(row: PatientRow): AuditCase[] {
  const issues: AuditCase[] = [];

  if (row.accountRole === 'PATIENT' && row.accountSubjectId && !isUuid(row.accountSubjectId)) {
    issues.push(buildCase('patient_account_subject_legacy_non_uuid', 'high', row, {
      accountSubjectId: row.accountSubjectId,
    }));
  }
  if (row.patientProfileSubjectId && !isUuid(row.patientProfileSubjectId)) {
    issues.push(buildCase('patient_role_profile_subject_not_uuid', 'high', row, {
      patientProfileSubjectId: row.patientProfileSubjectId,
    }));
  }
  if (row.patientAccessSubjectId && !isUuid(row.patientAccessSubjectId)) {
    issues.push(buildCase('patient_access_subject_not_uuid', 'high', row, {
      patientAccessSubjectId: row.patientAccessSubjectId,
    }));
  }
  if (row.patientProfileSubjectId && isUuid(row.patientProfileSubjectId) && !row.patientByProfileId) {
    issues.push(buildCase('patient_role_profile_subject_missing_in_users', 'high', row, {
      patientProfileSubjectId: row.patientProfileSubjectId,
    }));
  }
  if (row.patientAccessSubjectId && isUuid(row.patientAccessSubjectId) && !row.patientByAccessId) {
    issues.push(buildCase('patient_access_subject_missing_in_users', 'high', row, {
      patientAccessSubjectId: row.patientAccessSubjectId,
    }));
  }
  if (!row.patientByAuthId) {
    issues.push(buildCase('patient_auth_link_missing_in_users', 'medium', row, {
      patientProfileSubjectId: row.patientProfileSubjectId,
      patientAccessSubjectId: row.patientAccessSubjectId,
    }));
  }
  if (
    row.patientByAuthId &&
    row.patientProfileSubjectId &&
    row.patientByAuthId !== row.patientProfileSubjectId
  ) {
    issues.push(buildCase('patient_auth_link_mismatch_with_role_profile', 'high', row, {
      patientByAuthId: row.patientByAuthId,
      patientProfileSubjectId: row.patientProfileSubjectId,
    }));
  }
  if (
    row.patientByAuthId &&
    row.patientAccessSubjectId &&
    row.patientByAuthId !== row.patientAccessSubjectId
  ) {
    issues.push(buildCase('patient_auth_link_mismatch_with_product_access', 'high', row, {
      patientByAuthId: row.patientByAuthId,
      patientAccessSubjectId: row.patientAccessSubjectId,
    }));
  }
  if (
    row.patientProfileSubjectId &&
    row.patientAccessSubjectId &&
    row.patientProfileSubjectId !== row.patientAccessSubjectId
  ) {
    issues.push(buildCase('patient_role_profile_access_mismatch', 'high', row, {
      patientProfileSubjectId: row.patientProfileSubjectId,
      patientAccessSubjectId: row.patientAccessSubjectId,
    }));
  }

  return issues;
}

function classifyDoctorRow(row: DoctorRow): AuditCase[] {
  const issues: AuditCase[] = [];
  const profileDoctorId = row.doctorProfileDoctorId ?? row.doctorProfileSubjectId;

  if (row.accountRole === 'DOCTOR' && !row.doctorByAuthId) {
    issues.push(buildCase('doctor_auth_link_missing_in_doctors', 'high', row, {
      accountDoctorId: row.accountDoctorId,
    }));
  }
  if (row.accountRole === 'DOCTOR' && !row.accountDoctorId) {
    issues.push(buildCase('doctor_account_missing_doctor_id', 'high', row, {}));
  }
  if (row.accountDoctorId && !row.doctorByAccountDoctorId) {
    issues.push(buildCase('doctor_account_doctor_id_missing_in_doctors', 'high', row, {
      accountDoctorId: row.accountDoctorId,
    }));
  }
  if (!profileDoctorId) {
    issues.push(buildCase('doctor_role_profile_missing', 'medium', row, {}));
  } else if (!isUuid(profileDoctorId)) {
    issues.push(buildCase('doctor_role_profile_subject_not_uuid', 'high', row, {
      profileDoctorId,
    }));
  } else if (!row.doctorByProfileId) {
    issues.push(buildCase('doctor_role_profile_subject_missing_in_doctors', 'high', row, {
      profileDoctorId,
    }));
  }
  if (row.doctorAccessSubjectId && !isUuid(row.doctorAccessSubjectId)) {
    issues.push(buildCase('doctor_access_subject_not_uuid', 'high', row, {
      doctorAccessSubjectId: row.doctorAccessSubjectId,
    }));
  }
  if (row.doctorAccessSubjectId && isUuid(row.doctorAccessSubjectId) && !row.doctorByAccessId) {
    issues.push(buildCase('doctor_access_subject_missing_in_doctors', 'high', row, {
      doctorAccessSubjectId: row.doctorAccessSubjectId,
    }));
  }
  if (profileDoctorId && row.doctorAccessSubjectId && profileDoctorId !== row.doctorAccessSubjectId) {
    issues.push(buildCase('doctor_role_profile_access_mismatch', 'high', row, {
      profileDoctorId,
      doctorAccessSubjectId: row.doctorAccessSubjectId,
    }));
  }
  if (row.doctorByAuthId && row.accountDoctorId && row.doctorByAuthId !== row.accountDoctorId) {
    issues.push(buildCase('doctor_auth_link_mismatch_with_account', 'high', row, {
      doctorByAuthId: row.doctorByAuthId,
      accountDoctorId: row.accountDoctorId,
    }));
  }

  return issues;
}

function buildCase(
  type: string,
  severity: 'high' | 'medium',
  row: { accountId: string; email: string },
  details: Record<string, string | null>,
): AuditCase {
  return {
    type,
    severity,
    accountId: row.accountId,
    email: row.email,
    details,
  };
}

function matchesFilters(item: AuditCase) {
  if (accountIdFilter && item.accountId !== accountIdFilter) return false;
  if (emailFilter && item.email.toLowerCase() !== emailFilter) return false;
  return true;
}

function matchesRowFilter(item: { accountId: string; email: string }) {
  if (accountIdFilter && item.accountId !== accountIdFilter) return false;
  if (emailFilter && item.email.toLowerCase() !== emailFilter) return false;
  return true;
}

function summarize(cases: AuditCase[]) {
  const byType = new Map<
    string,
    { severity: 'high' | 'medium'; items: AuditCase[]; accounts: Set<string> }
  >();

  for (const item of cases) {
    const existing = byType.get(item.type) ?? {
      severity: item.severity,
      items: [],
      accounts: new Set<string>(),
    };
    existing.items.push(item);
    existing.accounts.add(item.accountId);
    byType.set(item.type, existing);
  }

  return [...byType.entries()]
    .map(([type, value]) => ({
      type,
      severity: value.severity,
      count: value.items.length,
      affectedAccounts: value.accounts.size,
      examples: value.items.slice(0, exampleLimit),
    }))
    .sort((a, b) => {
      if (a.severity !== b.severity) return a.severity === 'high' ? -1 : 1;
      return b.count - a.count;
    });
}

function isUuid(value: string) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
    value.trim(),
  );
}

function parsePositiveInt(value?: string) {
  if (!value?.trim()) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : undefined;
}

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(async () => {
    await prisma.$disconnect();
  });
