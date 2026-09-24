import { ApiPropertyOptional } from '@nestjs/swagger';
import { ScanStatus, ScanType } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsEnum, IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';

export class ListScansQuery {
  @ApiPropertyOptional({ description: 'Filtrar por activo' })
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({ enum: ScanStatus })
  @IsOptional()
  @IsEnum(ScanStatus)
  status?: ScanStatus;

  @ApiPropertyOptional({ enum: ScanType })
  @IsOptional()
  @IsEnum(ScanType)
  type?: ScanType;

  @ApiPropertyOptional({ default: 1, minimum: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page: number = 1;

  @ApiPropertyOptional({ default: 20, minimum: 1, maximum: 100 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  pageSize: number = 20;
}
