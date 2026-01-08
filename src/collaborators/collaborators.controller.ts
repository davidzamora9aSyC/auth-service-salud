import { Body, Controller, Delete, Get, Param, Patch, Post, Query } from '@nestjs/common';
import { CollaboratorsService } from './collaborators.service';
import { CreateCollaboratorInviteDto } from './dto/create-collaborator-invite.dto';
import { UpdateCollaboratorDto } from './dto/update-collaborator.dto';

@Controller('collaborators')
export class CollaboratorsController {
  constructor(private readonly collaboratorsService: CollaboratorsService) {}

  @Post('invites')
  createInvite(@Body() dto: CreateCollaboratorInviteDto) {
    return this.collaboratorsService.createInvite(dto);
  }

  @Get('invites/:token')
  getInvite(@Param('token') token: string) {
    return this.collaboratorsService.getInviteByToken(token);
  }

  @Get()
  listCollaborators(@Query('doctorId') doctorId: string) {
    return this.collaboratorsService.listCollaborators(doctorId);
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
