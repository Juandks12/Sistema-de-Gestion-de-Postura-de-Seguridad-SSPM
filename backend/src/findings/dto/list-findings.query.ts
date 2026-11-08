import { ApiPropertyOptional } from '@nestjs/swagger';
import { FindingCategory, FindingSeverity, FindingStatus } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsEnum, IsIn, IsInt, IsOptional, IsString, Max, MaxLength, Min } from 'class-validator';
import { ComplianceFramework } from '../../compliance/compliance.catalog';

export const SLA_STATUSES = ['OVERDUE', 'APPROACHING', 'ON_TRACK', 'NO_SLA'] as const;
export type SlaStatusQuery = (typeof SLA_STATUSES)[number];

export const EFFORT_LEVELS = ['QUICK_WIN', 'MODERATE', 'STRUCTURAL'] as const;
export type EffortLevelQuery = (typeof EFFORT_LEVELS)[number];

export const FINDING_DOMAINS = ['perimeter', 'cloud', 'manual', 'threat'] as const;
export type FindingDomainQuery = (typeof FINDING_DOMAINS)[number];

export const FINDING_SOURCES = [
  'PERIMETER_SCAN',
  'CLOUD_CSPM',
  'THREAT_MALWARE_LAB',
  'MANUAL_AUDIT',
] as const;
export type FindingSourceType = (typeof FINDING_SOURCES)[number];

export class ListFindingsQuery {
  @ApiPropertyOptional({ description: 'Filtrar por activo' })
  @IsOptional()
  @IsString()
  assetId?: string;

  @ApiPropertyOptional({
    enum: FINDING_DOMAINS,
    description: 'Filtrar por ámbito: perímetro externo, seguridad cloud (CSPM), auditoría manual o amenazas/malware',
  })
  @IsOptional()
  @IsIn(FINDING_DOMAINS)
  domain?: FindingDomainQuery;

  @ApiPropertyOptional({
    enum: FINDING_SOURCES,
    description: 'Filtrar por fuente de origen del hallazgo',
  })
  @IsOptional()
  @IsIn(FINDING_SOURCES)
  sourceType?: FindingSourceType;

  @ApiPropertyOptional({
    enum: ComplianceFramework,
    description: 'Filtrar hallazgos que impactan un marco normativo (ISO_27001, PCI_DSS, SOC_2, NIST_CSF, CIS_CONTROLS)',
  })
  @IsOptional()
  @IsEnum(ComplianceFramework)
  framework?: ComplianceFramework;

  @ApiPropertyOptional({
    description: 'Filtrar por código de control normativo (p. ej. A.8.24, 4.2.1, PR.DS-01)',
  })
  @IsOptional()
  @IsString()
  @MaxLength(60)
  controlCode?: string;

  @ApiPropertyOptional({
    description: 'Búsqueda por texto libre en título, ruleId, ubicación o descripción',
  })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  search?: string;

  @ApiPropertyOptional({ description: 'Filtrar por cuenta cloud conectada (UUID)' })
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

  @ApiPropertyOptional({ enum: EFFORT_LEVELS, description: 'Filtrar por nivel de esfuerzo de remediación (Quick Wins vs Mejoras Estructurales)' })
  @IsOptional()
  @IsIn(EFFORT_LEVELS)
  effortLevel?: EffortLevelQuery;

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
