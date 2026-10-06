import { ApiPropertyOptional } from '@nestjs/swagger';
import { FindingCategory, FindingSeverity, FindingStatus } from '@prisma/client';
import { IsDateString, IsEnum, IsIn, IsOptional, IsUUID } from 'class-validator';

export class ExportFindingsQuery {
  @ApiPropertyOptional({ enum: ['csv'], default: 'csv', description: 'Formato de exportación' })
  @IsOptional()
  @IsIn(['csv'])
  format?: string = 'csv';

  @ApiPropertyOptional({ description: 'Filtrar por activo' })
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({ enum: FindingSeverity })
  @IsOptional()
  @IsEnum(FindingSeverity)
  severity?: FindingSeverity;

  @ApiPropertyOptional({ enum: FindingStatus, description: 'Por defecto se listan todos los estados' })
  @IsOptional()
  @IsEnum(FindingStatus)
  status?: FindingStatus;

  @ApiPropertyOptional({ enum: FindingCategory })
  @IsOptional()
  @IsEnum(FindingCategory)
  category?: FindingCategory;

  @ApiPropertyOptional({ description: 'Filtrar por usuario asignado' })
  @IsOptional()
  @IsUUID()
  assignedToId?: string;

  @ApiPropertyOptional({ description: 'Filtrar por fecha de detección inicial (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  fromDate?: string;

  @ApiPropertyOptional({ description: 'Filtrar por fecha de detección final (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  toDate?: string;

  @ApiPropertyOptional({ description: 'Alias para fromDate (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  from?: string;

  @ApiPropertyOptional({ description: 'Alias para toDate (ISO 8601)' })
  @IsOptional()
  @IsDateString()
  to?: string;
}
