import { ApiPropertyOptional } from '@nestjs/swagger';
import { FindingCategory, FindingSeverity, FindingStatus } from '@prisma/client';
import { IsDateString, IsEnum, IsIn, IsOptional, IsString, MaxLength } from 'class-validator';
import { ComplianceFramework } from '../../compliance/compliance.catalog';
import {
  EFFORT_LEVELS,
  EffortLevelQuery,
  FINDING_DOMAINS,
  FINDING_SOURCES,
  FindingDomainQuery,
  FindingSourceType,
  SLA_STATUSES,
  SlaStatusQuery,
} from './list-findings.query';

export class ExportFindingsQuery {
  @ApiPropertyOptional({ enum: ['csv'], default: 'csv', description: 'Formato de exportación' })
  @IsOptional()
  @IsIn(['csv'])
  format?: string = 'csv';

  @ApiPropertyOptional({ description: 'Filtrar por activo' })
  @IsOptional()
  @IsString()
  assetId?: string;

  @ApiPropertyOptional({ enum: FINDING_DOMAINS })
  @IsOptional()
  @IsIn(FINDING_DOMAINS)
  domain?: FindingDomainQuery;

  @ApiPropertyOptional({ enum: FINDING_SOURCES })
  @IsOptional()
  @IsIn(FINDING_SOURCES)
  sourceType?: FindingSourceType;

  @ApiPropertyOptional({ enum: ComplianceFramework })
  @IsOptional()
  @IsEnum(ComplianceFramework)
  framework?: ComplianceFramework;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(60)
  controlCode?: string;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  @MaxLength(150)
  search?: string;

  @ApiPropertyOptional({ enum: EFFORT_LEVELS })
  @IsOptional()
  @IsIn(EFFORT_LEVELS)
  effortLevel?: EffortLevelQuery;

  @ApiPropertyOptional()
  @IsOptional()
  @IsString()
  cloudAccountId?: string;

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

  @ApiPropertyOptional({ description: 'Filtrar por usuario asignado (UUID o "unassigned" para no asignados)' })
  @IsOptional()
  @IsString()
  assignedToId?: string;

  @ApiPropertyOptional({ enum: SLA_STATUSES, description: 'Filtrar por cumplimiento de SLA' })
  @IsOptional()
  @IsIn(SLA_STATUSES)
  slaStatus?: SlaStatusQuery;

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
