import { Body, Controller, Get, Headers, Param, Patch, Post, Query, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CreateCommercialAccountDto } from './dto/create-commercial-account.dto';
import { ListCommercialAccountsDto } from './dto/list-commercial-accounts.dto';

const assertAdminRole = (role?: string) => {
  const normalizedRole = role?.toUpperCase();
  if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
    throw new UnauthorizedException('No autorizado');
  }
};

@Controller()
export class AdminCommercialAccountsController {
  constructor(private readonly authService: AuthService) {}

  @Post('admin/commercial-accounts')
  createCommercialAccount(
    @Body() dto: CreateCommercialAccountDto,
    @Headers('x-role') role?: string,
  ) {
    assertAdminRole(role);
    return this.authService.adminCreateCommercialAccount(dto);
  }

  @Get('admin/commercial-accounts')
  listCommercialAccounts(
    @Query() query: ListCommercialAccountsDto,
    @Headers('x-role') role?: string,
  ) {
    assertAdminRole(role);
    return this.authService.adminListCommercialAccounts(query);
  }
}
