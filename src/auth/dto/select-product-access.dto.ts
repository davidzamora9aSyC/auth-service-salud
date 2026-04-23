import { ProductCode, ProductRole } from '@prisma/client';
import { IsEnum, IsOptional, IsString, MinLength } from 'class-validator';

export class SelectProductAccessDto {
  @IsString()
  @MinLength(10)
  refreshToken!: string;

  @IsEnum(ProductCode)
  product!: ProductCode;

  @IsEnum(ProductRole)
  role!: ProductRole;

  @IsOptional()
  @IsString()
  accessId?: string;
}

