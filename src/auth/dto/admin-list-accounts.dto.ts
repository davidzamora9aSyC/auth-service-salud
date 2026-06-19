import { IsBoolean, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

export class AdminListAccountsDto {
  @IsOptional()
  @IsInt()
  @Min(1)
  page?: number;

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(100)
  limit?: number;

  @IsOptional()
  @IsString()
  role?: string;

  @IsOptional()
  @IsString()
  q?: string;

  @IsOptional()
  @IsBoolean()
  includeInsights?: boolean;
}
