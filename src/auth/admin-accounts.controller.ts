import { Body, Controller, Delete, Get, Headers, Param, Put, Query, Req, UnauthorizedException } from '@nestjs/common';
import type { Request } from 'express';
import { AuthService } from './auth.service';
import { AdminListAccountsDto } from './dto/admin-list-accounts.dto';
import { AdminUpdateAccountDto } from './dto/admin-update-account.dto';
import { AdminDeleteAccountDto } from './dto/admin-delete-account.dto';

@Controller()
export class AdminAccountsController {
  constructor(private readonly authService: AuthService) {}

  @Get('admin/accounts')
  listAccounts(
    @Query() query: AdminListAccountsDto,
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.adminListAccounts(query);
  }

  @Get('admin/accounts/:id')
  getAccount(
    @Param('id') id: string,
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.adminGetAccount(id);
  }

  @Put('admin/accounts/:id')
  updateAccount(
    @Param('id') id: string,
    @Body() dto: AdminUpdateAccountDto,
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.adminUpdateAccount(id, dto);
  }

  @Delete('admin/accounts/:id')
  deleteAccount(
    @Param('id') id: string,
    @Body() dto: AdminDeleteAccountDto,
    @Req() req: Request,
    @Headers('x-role') role?: string,
    @Headers('x-auth-user-id') requesterId?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.adminDeleteAccount(id, dto, requesterId ?? null, {
      ip: req.ip,
      forwardedFor: req.headers['x-forwarded-for'] as string | undefined,
      userAgent: req.headers['user-agent'],
    });
  }
}
