import { ApiPropertyOptional } from '@nestjs/swagger';
import { FindingSeverity, FindingStatus } from '@prisma/client';
import { Type } from 'class-transformer';
import { IsDateString, IsEnum, IsInt, IsOptional, IsString, IsUUID, Max, Min } from 'class-validator';

export class PublicFindingsQueryDto {
  @ApiPropertyOptional({
    description: 'Fecha ISO-8601 a partir de la cual consultar cambios (cursor incremental)',
    example: '2026-10-01T00:00:00Z',
  })
  @IsOptional()
  @IsDateString({}, { message: 'since debe ser una fecha ISO válida' })
  since?: string;

  @ApiPropertyOptional({
    description: 'Filtrar por estado del hallazgo',
    enum: FindingStatus,
  })
  @IsOptional()
  @IsEnum(FindingStatus)
  status?: FindingStatus;

  @ApiPropertyOptional({
    description: 'Filtrar por severidad',
    enum: FindingSeverity,
  })
  @IsOptional()
  @IsEnum(FindingSeverity)
  severity?: FindingSeverity;

  @ApiPropertyOptional({
    description: 'Filtrar por identificador único del activo',
  })
  @IsOptional()
  @IsUUID('4')
  assetId?: string;

  @ApiPropertyOptional({
    description: 'Límite de resultados a retornar (máximo 1000)',
    default: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1000)
  limit: number = 100;

  @ApiPropertyOptional({
    description: 'Formato de entrega: "json" (objeto con metadata) o "ndjson" (Newline Delimited JSON)',
    enum: ['json', 'ndjson'],
    default: 'json',
  })
  @IsOptional()
  @IsString()
  format?: 'json' | 'ndjson';
}

export class PublicAlertsQueryDto {
  @ApiPropertyOptional({
    description: 'Fecha ISO-8601 a partir de la cual consultar alertas (cursor incremental)',
    example: '2026-10-01T00:00:00Z',
  })
  @IsOptional()
  @IsDateString({}, { message: 'since debe ser una fecha ISO válida' })
  since?: string;

  @ApiPropertyOptional({
    description: 'Filtrar por severidad de la alerta',
    enum: FindingSeverity,
  })
  @IsOptional()
  @IsEnum(FindingSeverity)
  severity?: FindingSeverity;

  @ApiPropertyOptional({
    description: 'Límite de resultados a retornar (máximo 1000)',
    default: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1000)
  limit: number = 100;

  @ApiPropertyOptional({
    description: 'Formato de entrega: "json" o "ndjson"',
    enum: ['json', 'ndjson'],
    default: 'json',
  })
  @IsOptional()
  @IsString()
  format?: 'json' | 'ndjson';
}

export class PublicAssetsQueryDto {
  @ApiPropertyOptional({
    description: 'Límite de resultados a retornar (máximo 1000)',
    default: 100,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(1000)
  limit: number = 100;

  @ApiPropertyOptional({
    description: 'Formato de entrega: "json" o "ndjson"',
    enum: ['json', 'ndjson'],
    default: 'json',
  })
  @IsOptional()
  @IsString()
  format?: 'json' | 'ndjson';
}
