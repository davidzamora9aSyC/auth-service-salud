import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  Account,
  AccountRole,
  ProductCode,
  ProductRole,
} from '@prisma/client';
import { PrismaService } from '../prisma/prisma.service';

export type RegistrationPrefillPayload = {
  email: string;
  phoneNumber?: string | null;
  fullName?: string | null;
};

type IdentityHint = {
  fullName?: string | null;
  phoneNumber?: string | null;
};

type KnownSubjectIds = {
  patientId: string | null;
  doctorId: string | null;
};

@Injectable()
export class RegistrationPrefillService {
  private readonly logger = new Logger(RegistrationPrefillService.name);
  private readonly usersBaseUrl: string;
  private readonly doctorsBaseUrl: string;
  private readonly meuredBaseUrl: string;
  private readonly meuredInternalApiKey: string;

  constructor(
    private readonly config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    this.usersBaseUrl =
      this.config.get<string>('USERS_BASE_URL') ??
      'http://users-service:3008/usersms';
    this.doctorsBaseUrl =
      this.config.get<string>('DOCTORS_BASE_URL') ??
      'http://doctors-service:3009/doctorsms';
    this.meuredBaseUrl =
      this.config.get<string>('MEURED_BASE_URL') ??
      'http://meured-service:3032/meuredms';
    this.meuredInternalApiKey =
      this.config.get<string>('MEURED_INTERNAL_API_KEY') ??
      this.config.get<string>('INTERNAL_API_KEY') ??
      'local-internal-meured';
  }

  async build(account: Account): Promise<RegistrationPrefillPayload> {
    const subjectIds = await this.resolveKnownSubjectIds(account);

    const [
      doctorByAuth,
      patientByAuth,
      meured,
      doctorById,
      patientById,
    ] = await Promise.all([
      this.fetchDoctorIdentity(account.id),
      this.fetchPatientIdentityByAuthUserId(account.id),
      this.fetchMeuredIdentity(account.id),
      subjectIds.doctorId
        ? this.fetchDoctorIdentityById(subjectIds.doctorId)
        : Promise.resolve(null),
      subjectIds.patientId
        ? this.fetchPatientIdentityById(subjectIds.patientId)
        : Promise.resolve(null),
    ]);

    const doctor = doctorByAuth ?? doctorById;
    const patient = patientByAuth ?? patientById;

    const fullName =
      this.pickText(doctor?.fullName) ??
      this.pickText(patient?.fullName) ??
      this.pickText(meured?.fullName) ??
      null;

    const phoneNumber =
      this.pickText(account.phoneNumber) ??
      this.pickText(doctor?.phoneNumber) ??
      this.pickText(patient?.phoneNumber) ??
      null;

    return {
      email: account.email.trim().toLowerCase(),
      phoneNumber,
      fullName,
    };
  }

  async ensureMeuredProfile(
    authUserId: string,
    options: {
      firstName?: string;
      lastName?: string;
      productRole: ProductRole;
    },
  ) {
    const firstName = options.firstName?.trim();
    const lastName = options.lastName?.trim();
    if (!firstName && !lastName) {
      return;
    }

    const kind = this.mapMeuredProductRoleToKind(options.productRole);
    if (!kind) {
      return;
    }

    const url = `${this.meuredBaseUrl.replace(/\/$/, '')}/internal/profiles/${encodeURIComponent(authUserId)}/bootstrap`;
    try {
      const response = await fetch(url, {
        method: 'PUT',
        headers: {
          'content-type': 'application/json',
          'x-internal-api-key': this.meuredInternalApiKey,
        },
        body: JSON.stringify({ firstName, lastName, kind }),
      });
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(
          `No se pudo inicializar perfil MeuRed para ${authUserId} (status ${response.status}): ${body}`,
        );
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`No se pudo inicializar perfil MeuRed para ${authUserId}: ${message}`);
    }
  }

  async disableMeuredProfile(authUserId: string) {
    const url = `${this.meuredBaseUrl.replace(/\/$/, '')}/internal/profiles/${encodeURIComponent(authUserId)}`;
    const response = await fetch(url, {
      method: 'DELETE',
      headers: {
        'x-internal-api-key': this.meuredInternalApiKey,
      },
    });

    if (!response.ok) {
      const body = await response.text();
      throw new Error(
        `No se pudo desactivar perfil MeuRed (status ${response.status}): ${body}`,
      );
    }

    return (await response.json()) as {
      ok: boolean;
      membershipsDeleted: number;
      settingsDeleted: number;
      verificationsDeleted: number;
      statsDeleted: number;
      profilesDeleted: number;
    };
  }

  private async resolveKnownSubjectIds(account: Account): Promise<KnownSubjectIds> {
    const [roleProfiles, productAccesses] = await Promise.all([
      this.prisma.accountRoleProfile.findMany({
        where: { accountId: account.id },
        select: { role: true, subjectId: true },
      }),
      this.prisma.accountProductAccess.findMany({
        where: { accountId: account.id, status: 'ACTIVE' },
        select: { product: true, role: true, subjectId: true },
      }),
    ]);

    const patientRoleProfile = roleProfiles.find(
      (profile) => profile.role === AccountRole.PATIENT,
    );
    const patientProductAccess = productAccesses.find(
      (access) => access.product === ProductCode.PATIENT_PORTAL,
    );

    const doctorRoleProfile = roleProfiles.find(
      (profile) => profile.role === AccountRole.DOCTOR,
    );
    const doctorMeudocRoles = new Set<ProductRole>([
      ProductRole.DOCTOR,
      ProductRole.RESEARCHER,
      ProductRole.STUDENT,
    ]);
    const doctorProductAccess = productAccesses.find(
      (access) =>
        access.product === ProductCode.MEUDOC_PRO && doctorMeudocRoles.has(access.role),
    );

    const patientProfileSubjectId = this.pickText(patientRoleProfile?.subjectId);
    const patientAccessSubjectId = this.pickText(patientProductAccess?.subjectId);
    const patientId =
      (patientProfileSubjectId && this.isUuid(patientProfileSubjectId)
        ? patientProfileSubjectId
        : null) ??
      (patientAccessSubjectId && this.isUuid(patientAccessSubjectId)
        ? patientAccessSubjectId
        : null) ??
      null;

    const doctorId =
      this.pickText(doctorRoleProfile?.subjectId) ??
      this.pickText(account.doctorId) ??
      this.pickText(doctorProductAccess?.subjectId) ??
      null;

    return { patientId, doctorId };
  }

  private mapMeuredProductRoleToKind(role: ProductRole) {
    if (role === ProductRole.DOCTOR) return 'DOCTOR';
    if (role === ProductRole.RESEARCHER) return 'RESEARCHER';
    if (role === ProductRole.STUDENT) return 'STUDENT';
    return null;
  }

  private pickText(value?: string | null) {
    const trimmed = value?.trim();
    return trimmed || null;
  }

  private isUuid(value?: string | null) {
    if (!value) return false;
    return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value.trim(),
    );
  }

  private composeFullName(
    fullName?: string | null,
    firstName?: string | null,
    lastName?: string | null,
    displayName?: string | null,
  ) {
    const safeFull = fullName?.trim();
    if (safeFull) return safeFull;
    const safeDisplay = displayName?.trim();
    if (safeDisplay) return safeDisplay;
    const composed = [firstName, lastName]
      .map((value) => value?.trim() || '')
      .filter(Boolean)
      .join(' ')
      .trim();
    return composed || null;
  }

  private mapPatientIdentityPayload(data: {
    patientId?: string | null;
    fullName?: string | null;
    firstName?: string | null;
    lastName?: string | null;
    phoneNumber?: string | null;
  }): IdentityHint | null {
    if (!data.patientId) return null;
    return {
      fullName: this.composeFullName(data.fullName, data.firstName, data.lastName),
      phoneNumber: data.phoneNumber ?? null,
    };
  }

  private async fetchDoctorIdentity(authUserId: string): Promise<IdentityHint | null> {
    try {
      const response = await fetch(
        `${this.doctorsBaseUrl.replace(/\/$/, '')}/doctors/me?authUserId=${encodeURIComponent(authUserId)}`,
        { headers: { 'x-role': 'SYSTEM' } },
      );
      if (response.status === 404) return null;
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`Doctor identity lookup failed (${response.status}): ${body}`);
        return null;
      }
      const data = (await response.json()) as {
        fullName?: string | null;
        phoneNumber?: string | null;
      };
      return {
        fullName: data.fullName ?? null,
        phoneNumber: data.phoneNumber ?? null,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Doctor identity lookup error: ${message}`);
      return null;
    }
  }

  private async fetchDoctorIdentityById(doctorId: string): Promise<IdentityHint | null> {
    try {
      const response = await fetch(
        `${this.doctorsBaseUrl.replace(/\/$/, '')}/doctors/${encodeURIComponent(doctorId)}`,
        { headers: { 'x-role': 'SYSTEM' } },
      );
      if (response.status === 404) return null;
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`Doctor identity by id lookup failed (${response.status}): ${body}`);
        return null;
      }
      const data = (await response.json()) as {
        fullName?: string | null;
        phoneNumber?: string | null;
      };
      return {
        fullName: data.fullName ?? null,
        phoneNumber: data.phoneNumber ?? null,
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Doctor identity by id lookup error: ${message}`);
      return null;
    }
  }

  private async fetchPatientIdentityByAuthUserId(authUserId: string): Promise<IdentityHint | null> {
    try {
      const response = await fetch(
        `${this.usersBaseUrl.replace(/\/$/, '')}/patients/internal/by-auth-user/${encodeURIComponent(authUserId)}`,
        { headers: { 'x-role': 'SYSTEM' } },
      );
      if (response.status === 404) return null;
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`Patient identity lookup failed (${response.status}): ${body}`);
        return null;
      }
      const data = (await response.json()) as {
        patientId?: string | null;
        fullName?: string | null;
        firstName?: string | null;
        lastName?: string | null;
        phoneNumber?: string | null;
      };
      return this.mapPatientIdentityPayload(data);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Patient identity lookup error: ${message}`);
      return null;
    }
  }

  private async fetchPatientIdentityById(patientId: string): Promise<IdentityHint | null> {
    try {
      const response = await fetch(
        `${this.usersBaseUrl.replace(/\/$/, '')}/patients/internal/by-id/${encodeURIComponent(patientId)}`,
        { headers: { 'x-role': 'SYSTEM' } },
      );
      if (response.status === 404) return null;
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`Patient identity by id lookup failed (${response.status}): ${body}`);
        return null;
      }
      const data = (await response.json()) as {
        patientId?: string | null;
        fullName?: string | null;
        firstName?: string | null;
        lastName?: string | null;
        phoneNumber?: string | null;
      };
      return this.mapPatientIdentityPayload(data);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`Patient identity by id lookup error: ${message}`);
      return null;
    }
  }

  private async fetchMeuredIdentity(authUserId: string): Promise<IdentityHint | null> {
    try {
      const response = await fetch(
        `${this.meuredBaseUrl.replace(/\/$/, '')}/internal/profiles/${encodeURIComponent(authUserId)}`,
        { headers: { 'x-internal-api-key': this.meuredInternalApiKey } },
      );
      if (response.status === 404) return null;
      if (!response.ok) {
        const body = await response.text();
        this.logger.warn(`MeuRed identity lookup failed (${response.status}): ${body}`);
        return null;
      }
      const data = (await response.json()) as {
        profile?: {
          firstName?: string | null;
          lastName?: string | null;
          displayName?: string | null;
        } | null;
      };
      const profile = data.profile;
      if (!profile) return null;
      const fullName = this.composeFullName(
        null,
        profile.firstName,
        profile.lastName,
        profile.displayName,
      );
      if (!fullName) return null;
      return { fullName };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.logger.warn(`MeuRed identity lookup error: ${message}`);
      return null;
    }
  }
}
