export type DoctorOnboardingInviteOnboardingInfo = {
  doctorId: string;
  status?: string | null;
  profileStatus?: string | null;
  onboardingStep?: string | null;
};

export type DoctorOnboardingInviteAdminItem = {
  id: string;
  doctorId: string;
  email: string;
  phoneNumber: string | null;
  firstName: string | null;
  lastName: string | null;
  status: string;
  preferredPlanCode: string | null;
  trialDurationValue: number | null;
  trialDurationUnit: 'DAY' | 'MONTH' | null;
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
  onboarding?: DoctorOnboardingInviteOnboardingInfo | null;
};

export type DoctorOnboardingInviteAdminListResponse = {
  items: DoctorOnboardingInviteAdminItem[];
  page: number;
  limit: number;
  total: number;
};
