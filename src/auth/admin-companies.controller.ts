import { Controller, Delete, Headers, Param, Post, Body, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller()
export class AdminCompaniesController {
  constructor(private readonly authService: AuthService) {}

  @Post('admin/companies/search')
  listCompanies(
    @Body() body: { page?: number; limit?: number; q?: string },
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.adminListEmployerCompanies(body);
  }

  @Delete('admin/companies/:id')
  deleteCompany(
    @Param('id') id: string,
    @Headers('x-role') role?: string,
  ) {
    const normalizedRole = role?.toUpperCase();
    if (normalizedRole !== 'ADMIN' && normalizedRole !== 'SYSTEM') {
      throw new UnauthorizedException('No autorizado');
    }
    return this.authService.adminArchiveEmployerCompany(id);
  }
}
