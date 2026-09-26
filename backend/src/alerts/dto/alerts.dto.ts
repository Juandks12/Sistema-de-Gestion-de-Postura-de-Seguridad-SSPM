import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { AlertChannelType, AlertType, FindingSeverity } from '@prisma/client';
import { Transform, Type } from 'class-transformer';
import { IsBoolean, IsEnum, IsInt, IsOptional, IsString, IsUUID, Max, MaxLength, Min, MinLength } from 'class-validator';

/** Convierte "true"/"false" de la query string sin depender de la conversión implícita. */
function toBoolean({ obj, key }: { obj: Record<string, unknown>; key: string }): unknown {
  const value = obj[key];
  if (value === 'true' || value === true) return true;
  if (value === 'false' || value === false) return false;
  return value;
}

function trim({ value }: { value: unknown }): unknown {
  return typeof value === 'string' ? value.trim() : value;
}

export class ListAlertsQuery {
  @ApiPropertyOptional({ description: 'true = solo revisadas, false = solo pendientes' })
  @IsOptional()
  @Transform(toBoolean)
  @IsBoolean()
  acknowledged?: boolean;

  @ApiPropertyOptional({ enum: AlertType })
  @IsOptional()
  @IsEnum(AlertType)
  type?: AlertType;

  @ApiPropertyOptional({ enum: FindingSeverity })
  @IsOptional()
  @IsEnum(FindingSeverity)
  severity?: FindingSeverity;

  @ApiPropertyOptional({ description: 'Filtrar por activo' })
  @IsOptional()
  @IsUUID()
  assetId?: string;

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

export class CreateAlertChannelDto {
  @ApiProperty({ enum: AlertChannelType, example: AlertChannelType.WEBHOOK })
  @IsEnum(AlertChannelType)
  type!: AlertChannelType;

  @ApiProperty({ example: 'Canal #seguridad en Slack' })
  @Transform(trim)
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name!: string;

  @ApiProperty({
    description: 'EMAIL: destinatarios separados por coma. WEBHOOK: URL https (Slack, Discord o JSON genérico).',
    example: 'https://hooks.slack.com/services/T000/B000/XXXX',
  })
  @Transform(trim)
  @IsString()
  @MinLength(3)
  @MaxLength(1000)
  target!: string;

  @ApiPropertyOptional({ enum: FindingSeverity, default: FindingSeverity.HIGH, description: 'Severidad mínima que se notifica' })
  @IsOptional()
  @IsEnum(FindingSeverity)
  minSeverity?: FindingSeverity;

  @ApiPropertyOptional({ default: true })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

export class UpdateAlertChannelDto {
  @ApiPropertyOptional()
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MinLength(2)
  @MaxLength(100)
  name?: string;

  @ApiPropertyOptional({ description: 'Nuevo destino. Si se omite se conserva el actual.' })
  @IsOptional()
  @Transform(trim)
  @IsString()
  @MinLength(3)
  @MaxLength(1000)
  target?: string;

  @ApiPropertyOptional({ enum: FindingSeverity })
  @IsOptional()
  @IsEnum(FindingSeverity)
  minSeverity?: FindingSeverity;

  @ApiPropertyOptional()
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}
