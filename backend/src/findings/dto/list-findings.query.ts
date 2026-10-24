import { ApiPropertyOptional } from '@nestjs/swagger';
import { FindingCategory, FindingSeverity, FindingStatus } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsEnum, IsIn, IsInt, IsOptional, IsString, Max, Min } from 'class-validator';

export const SLA_STATUSES = ['OVERDUE', 'APPROACHING', 'ON_TRACK', 'NO_SLA'] as const;
export type SlaStatusQuery = (typeof SLA_STATUSES)[number];

export const EFFORT_LEVELS = ['QUICK_WIN', 'MODERATE', 'STRUCTURAL'] as const;
export type EffortLevelQuery = (typeof EFFORT_LEVELS)[number];

export const FINDING_DOMAINS = ['perimeter', 'cloud'] as const;
export type FindingDomainQuery = (typeof FINDING_DOMAINS)[number];

export class ListFindingsQuery {
  @ApiPropertyOptional({ description: 'Filtrar por activo' })
  @IsOptional()
  @IsString()
  assetId?: string;

  @ApiPropertyOptional({ enum: FINDING_DOMAINS, description: 'Filtrar por ámbito: perímetro externo o seguridad cloud (CSPM)' })
  @IsOptional()
  @IsIn(FINDING_DOMAINS)
  domain?: FindingDomainQuery;

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
