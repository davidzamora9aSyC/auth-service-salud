import {
  Body,
  Controller,
  Delete,
  Get,
  Headers,
  Param,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import { ClinicsService } from './clinics.service';
import { CreateClinicDto } from './dto/create-clinic.dto';
import { UpdateClinicDto } from './dto/update-clinic.dto';
import { InviteClinicDoctorDto } from './dto/invite-clinic-doctor.dto';
import { AddClinicAdminDto } from './dto/add-clinic-admin.dto';
import { CreateClinicLocationDto } from './dto/create-clinic-location.dto';
import { UpdateClinicLocationDto } from './dto/update-clinic-location.dto';
import { AssignClinicAgendaDto } from './dto/assign-clinic-agenda.dto';

@Controller('clinics')
export class ClinicsController {
  constructor(private readonly clinicsService: ClinicsService) {}

  @Post()
  createClinic(
    @Body() dto: CreateClinicDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.createClinic(dto, { role, authUserId, subjectId });
  }

  @Get(':clinicId')
  getClinic(
    @Param('clinicId') clinicId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.getClinic(clinicId, { role, authUserId, subjectId });
  }

  @Patch(':clinicId')
  updateClinic(
    @Param('clinicId') clinicId: string,
    @Body() dto: UpdateClinicDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.updateClinic(clinicId, dto, { role, authUserId, subjectId });
  }

  @Post(':clinicId/admins')
  addAdmin(
    @Param('clinicId') clinicId: string,
    @Body() dto: AddClinicAdminDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.addClinicAdmin(clinicId, dto, { role, authUserId, subjectId });
  }

  @Post(':clinicId/doctors/invites')
  inviteDoctor(
    @Param('clinicId') clinicId: string,
    @Body() dto: InviteClinicDoctorDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.inviteDoctor(clinicId, dto, { role, authUserId, subjectId });
  }

  @Get(':clinicId/doctors/invites')
  listDoctorInvites(
    @Param('clinicId') clinicId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.listDoctorInvites(clinicId, { role, authUserId, subjectId });
  }

  @Post('doctors/invites/:token/accept')
  acceptDoctorInvite(
    @Param('token') token: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.acceptDoctorInvite(token, { role, authUserId, subjectId });
  }

  @Get(':clinicId/doctors')
  listDoctors(
    @Param('clinicId') clinicId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.listDoctors(clinicId, { role, authUserId, subjectId });
  }

  @Delete(':clinicId/doctors/:doctorId')
  removeDoctor(
    @Param('clinicId') clinicId: string,
    @Param('doctorId') doctorId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.removeDoctor(clinicId, doctorId, { role, authUserId, subjectId });
  }

  @Get(':clinicId/locations')
  listLocations(
    @Param('clinicId') clinicId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.listLocations(clinicId, { role, authUserId, subjectId });
  }

  @Post(':clinicId/locations')
  createLocation(
    @Param('clinicId') clinicId: string,
    @Body() dto: CreateClinicLocationDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.createLocation(clinicId, dto, { role, authUserId, subjectId });
  }

  @Patch(':clinicId/locations/:locationId')
  updateLocation(
    @Param('clinicId') clinicId: string,
    @Param('locationId') locationId: string,
    @Body() dto: UpdateClinicLocationDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.updateLocation(clinicId, locationId, dto, { role, authUserId, subjectId });
  }

  @Delete(':clinicId/locations/:locationId')
  deleteLocation(
    @Param('clinicId') clinicId: string,
    @Param('locationId') locationId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.deleteLocation(clinicId, locationId, { role, authUserId, subjectId });
  }

  @Post(':clinicId/locations/:locationId/agendas')
  assignAgenda(
    @Param('clinicId') clinicId: string,
    @Param('locationId') locationId: string,
    @Body() dto: AssignClinicAgendaDto,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.assignAgenda(clinicId, locationId, dto, { role, authUserId, subjectId });
  }

  @Delete(':clinicId/locations/:locationId/agendas/:agendaId')
  unassignAgenda(
    @Param('clinicId') clinicId: string,
    @Param('locationId') locationId: string,
    @Param('agendaId') agendaId: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.unassignAgenda(clinicId, locationId, agendaId, { role, authUserId, subjectId });
  }

  @Get('agendas/:agendaId/scope')
  getAgendaScope(
    @Param('agendaId') agendaId: string,
    @Query('doctorId') doctorId?: string,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') authUserId?: string,
    @Headers('x-subject-id') subjectId?: string,
  ) {
    return this.clinicsService.getAgendaScope(agendaId, doctorId, {
      role,
      authUserId,
      subjectId,
    });
  }
}
