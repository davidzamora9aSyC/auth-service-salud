const { test } = require('node:test');
const assert = require('node:assert/strict');
const { ClinicDoctorIdentitiesService } = require('../dist/src/auth/clinic-doctor-identities.service');
const { AuthService } = require('../dist/src/auth/auth.service');
const { generateKeyPairSync } = require('node:crypto');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');

test('resuelve la identidad medica desde perfiles y accesos sin usar Account.role o Account.doctorId', async () => {
  let query;
  const service = Object.create(ClinicDoctorIdentitiesService.prototype);
  service.prisma = { account: { findMany: async (input) => {
    query = input;
    return [{ id: 'account', email: 'doctor@example.com',
      roleProfiles: [{ doctorId: 'doctor', subjectId: 'doctor' }],
      productAccesses: [{ subjectId: 'doctor' }] }];
  } } };
  assert.deepEqual(await service.find({ email: 'DOCTOR@example.com' }), [
    { accountId: 'account', email: 'doctor@example.com', doctorId: 'doctor', inconsistent: false },
  ]);
  assert.equal(query.where.email, 'doctor@example.com');
  assert.equal(query.select.role, undefined);
  assert.equal(query.select.doctorId, undefined);
});

test('detecta perfiles y accesos con diferentes identidades', async () => {
  const service = Object.create(ClinicDoctorIdentitiesService.prototype);
  service.prisma = { account: { findMany: async () => [{ id: 'account', email: 'doctor@example.com',
    roleProfiles: [{ doctorId: 'one', subjectId: 'one' }], productAccesses: [{ subjectId: 'two' }],
  }] } };
  assert.equal((await service.find({ accountId: 'account' }))[0].inconsistent, true);
  await assert.rejects(service.find({}), /un solo criterio/);
});

test('login de medico y JWT usan el perfil y el acceso aunque Account.doctorId sea nulo', async () => {
  const password = 'test-password';
  const account = {
    id: 'account', email: 'doctor@example.com', role: 'PATIENT', doctorId: null,
    subjectId: null, onboardingStatus: 'PENDING', status: 'ACTIVE', salt: 'salt',
    passwordHash: await argon2.hash(password + 'salt'), twoFactorEnabled: false,
  };
  const profile = { role: 'DOCTOR', doctorId: 'doctor', subjectId: 'doctor', onboardingStatus: 'COMPLETE' };
  const access = { id: 'access', accountId: account.id, product: 'MEUDOC_PRO', role: 'DOCTOR', subjectId: 'doctor', status: 'ACTIVE' };
  const service = Object.create(AuthService.prototype);
  service.privateKey = generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey;
  service.accessTtl = 900;
  service.refreshTtl = 3600;
  service.prisma = {
    account: { findUnique: async () => account },
    accountRoleProfile: { findUnique: async () => profile, findMany: async () => [profile] },
    accountProductAccess: { findMany: async () => [access] },
    refreshToken: { create: async () => ({}) },
  };
  service.recordLoginHistory = async () => {};
  const result = await service.login({ email: account.email, password, role: 'DOCTOR' });
  const claims = jwt.decode(result.accessToken);
  assert.equal(claims.doctorId, 'doctor');
  assert.equal(claims.productSubjectId, 'doctor');
  assert.equal(claims.onboardingRequired, false);
  assert.equal(result.account.doctorId, 'doctor');
});
