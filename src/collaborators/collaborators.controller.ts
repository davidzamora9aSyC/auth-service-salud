import { BadRequestException, Body, Controller, Delete, Get, Headers, Param, Patch, Post, Query } from '@nestjs/common';
import { CollaboratorsService } from './collaborators.service';
import { CreateCollaboratorInviteDto } from './dto/create-collaborator-invite.dto';
import { UpdateCollaboratorDto } from './dto/update-collaborator.dto';

@Controller('collaborators')
export class CollaboratorsController {
  constructor(private readonly collaboratorsService: CollaboratorsService) {}

  @Post('invites')
  async createInvite(
    @Body() dto: CreateCollaboratorInviteDto,
    @Headers('x-subject-id') subjectId?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    const doctorId = await this.collaboratorsService.resolveDoctorId({
      doctorId: dto.doctorId,
      subjectId,
      authUserId,
    });
    return this.collaboratorsService.createInvite({
      ...dto,
      doctorId,
    });
  }

  @Get('invites/:token')
  getInvite(@Param('token') token: string) {
    return this.collaboratorsService.getInviteByToken(token);
  }

  @Get()
  async listCollaborators(
    @Query('doctorId') doctorId: string | undefined,
    @Headers('x-subject-id') subjectId?: string,
    @Headers('x-auth-user-id') authUserId?: string,
  ) {
    const resolvedDoctorId = await this.collaboratorsService.resolveDoctorId({
      doctorId,
      subjectId,
      authUserId,
    });
    return this.collaboratorsService.listCollaborators(resolvedDoctorId);
  }

  @Patch(':collaboratorId')
  updateCollaborator(
    @Param('collaboratorId') collaboratorId: string,
    @Body() dto: UpdateCollaboratorDto,
  ) {
    return this.collaboratorsService.updateCollaborator(collaboratorId, dto);
  }

  @Delete(':collaboratorId')
  disableCollaborator(@Param('collaboratorId') collaboratorId: string) {
    return this.collaboratorsService.disableCollaborator(collaboratorId);
  }
}
