import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { FindingCategory, FindingSeverity } from '@prisma/client';
import { Type } from 'class-transformer';
import {
  IsArray,
  IsEnum,
  IsIn,
  IsISO8601,
  IsNotEmpty,
  IsNumber,
  IsObject,
  IsOptional,
  IsString,
  IsUUID,
  Max,
  MaxLength,
  Min,
} from 'class-validator';
import { EFFORT_LEVELS, EffortLevelQuery } from './list-findings.query';

export class CreateManualFindingDto {
  @ApiProperty({ description: 'UUID del activo afectado en la organización' })
  @IsUUID()
  assetId!: string;

  @ApiProperty({ example: 'Exposición de endpoint administrativo sin MFA en pasarela de pagos' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(200)
  title!: string;

  @ApiProperty({ example: 'Durante la auditoría de seguridad se identificó que el endpoint administrativo carece de segundo factor y control de tasa.' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(4000)
  description!: string;

  @ApiProperty({ example: 'Habilitar MFA obligatorio, restringir acceso mediante VPN/IP allowlist y aplicar rate-limiting estricto.' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(4000)
  recommendation!: string;

  @ApiProperty({ enum: FindingSeverity, example: FindingSeverity.HIGH })
  @IsEnum(FindingSeverity)
  severity!: FindingSeverity;

  @ApiProperty({ enum: FindingCategory, example: FindingCategory.SENSITIVE_PATH })
  @IsEnum(FindingCategory)
  category!: FindingCategory;

  @ApiProperty({ example: 'https://tienda.empresa.com/admin/billing' })
  @IsString()
  @IsNotEmpty()
  @MaxLength(500)
  location!: string;

  @ApiPropertyOptional({ example: 8.2, minimum: 0, maximum: 10 })
  @IsOptional()
  @Type(() => Number)
  @IsNumber()
  @Min(0)
  @Max(10)
  cvssScore?: number;

  @ApiPropertyOptional({ example: 'MANUAL-PENTEST-AUTH-01', description: 'Código de regla o referencia de auditoría (opcional)' })
  @IsOptional()
  @IsString()
  @MaxLength(60)
  ruleId?: string;

  @ApiPropertyOptional({ example: 'CWE-306: Missing Authentication for Critical Function' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  cweId?: string;

  @ApiPropertyOptional({ example: 'A07:2021 - Identification and Authentication Failures' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  owaspCategory?: string;

  @ApiPropertyOptional({ example: 'T1190 - Exploit Public-Facing Application' })
  @IsOptional()
  @IsString()
  @MaxLength(150)
  mitreAttackTechnique?: string;

  @ApiPropertyOptional({
    type: [String],
    example: ['ISO-A.8.5', 'PCI-Req-8.4.2'],
    description: 'IDs o códigos de controles normativos asociados (ISO 27001, PCI-DSS, NIST, CIS, SOC 2)',
  })
  @IsOptional()
  @IsArray()
  @IsString({ each: true })
  complianceControlIds?: string[];

  @ApiPropertyOptional({ example: 'Riesgo de acceso no autorizado a operaciones administrativas y conciliación de pagos.' })
  @IsOptional()
  @IsString()
  @MaxLength(1000)
  businessImpact?: string;

  @ApiPropertyOptional({ enum: EFFORT_LEVELS, example: 'MODERATE' })
  @IsOptional()
  @IsIn(EFFORT_LEVELS)
  effort?: EffortLevelQuery;

  @ApiPropertyOptional({ example: 'nginx -s reload # tras aplicar directiva allow/deny' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  remediationCli?: string;

  @ApiPropertyOptional({ description: 'UUID del responsable asignado para remediación' })
  @IsOptional()
  @IsUUID()
  assignedToId?: string;

  @ApiPropertyOptional({ description: 'Fecha límite SLA en formato ISO 8601 (se autocalcula según severidad si se omite)' })
  @IsOptional()
  @IsISO8601()
  dueDate?: string;

  @ApiPropertyOptional({ description: 'Evidencia técnica adicional estructurada en JSON' })
  @IsOptional()
  @IsObject()
  evidence?: Record<string, unknown>;
}
