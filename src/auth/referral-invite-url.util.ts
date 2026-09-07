const trimBase = (value: string) => value.trim().replace(/\/$/, '');

export function resolveReferralInvitePublicBaseUrl(): string {
  const raw = process.env.PUBLIC_APP_BASE_URL ?? '';
  return trimBase(raw);
}

export function buildPatientReferralInviteUrl(params: {
  token: string;
  firstName: string;
  lastName: string;
  email: string;
  phoneNumber: string;
}) {
  const base = resolveReferralInvitePublicBaseUrl();
  const query = new URLSearchParams({
    referralInviteToken: params.token,
    firstName: params.firstName,
    lastName: params.lastName,
    email: params.email,
    phoneNumber: params.phoneNumber,
  }).toString();
  const path = `/public/patient/register?${query}`;
  return base ? `${base}${path}` : path;
}

export function buildCompanyReferralInviteUrl(params: {
  token: string;
  firstName: string;
  lastName: string;
  email: string;
  phoneNumber: string;
  companyName: string;
  taxId: string;
}) {
  const base = resolveReferralInvitePublicBaseUrl();
  const query = new URLSearchParams({
    referralInviteToken: params.token,
    firstName: params.firstName,
    lastName: params.lastName,
    email: params.email,
    phoneNumber: params.phoneNumber,
    companyName: params.companyName,
    taxId: params.taxId,
  }).toString();
  const path = `/company/crear-cuenta?${query}`;
  return base ? `${base}${path}` : path;
}
