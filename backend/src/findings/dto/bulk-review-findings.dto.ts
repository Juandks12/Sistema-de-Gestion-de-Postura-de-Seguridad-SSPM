import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  ArrayMaxSize,
  ArrayMinSize,
  IsArray,
  IsIn,
  IsISO8601,
  IsOptional,
  IsString,
  IsUUID,
  MaxLength,
  ValidateIf,
} from 'class-validator';
import { REVIEWABLE_STATUSES } from './review-finding.dto';

export class BulkReviewFindingsDto {
  @ApiProperty({
    type: [String],
    description: 'Lista de IDs (UUID) de los hallazgos a actualizar en lote (máximo 100)',
  })
  @IsArray()
  @ArrayMinSize(1)
  @ArrayMaxSize(100)
  @IsUUID('4', { each: true })
  findingIds!: string[];

  @ApiPropertyOptional({ enum: REVIEWABLE_STATUSES })
  @IsOptional()
  @IsIn(REVIEWABLE_STATUSES)
  status?: (typeof REVIEWABLE_STATUSES)[number];

  @ApiPropertyOptional({ description: 'UUID del usuario responsable asignado (null para desasignar)' })
  @IsOptional()
  @ValidateIf((_, val) => val !== null && val !== undefined)
  @IsUUID()
  assignedToId?: string | null;

  @ApiPropertyOptional({ description: 'Fecha límite SLA (ISO 8601) o null para limpiar' })
  @IsOptional()
  @ValidateIf((_, val) => val !== null && val !== undefined)
  @IsISO8601()
  dueDate?: string | null;

  @ApiPropertyOptional({ description: 'Nota de revisión o justificación de aceptación de riesgo' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  note?: string;

  @ApiPropertyOptional({ description: 'Nota técnica del plan de remediación' })
  @IsOptional()
  @ValidateIf((_, val) => val !== null && val !== undefined)
  @IsString()
  @MaxLength(2000)
  remediationNote?: string | null;
}
