import { ApiPropertyOptional } from '@nestjs/swagger';
import { FindingStatus } from '@prisma/client';
import { IsIn, IsISO8601, IsOptional, IsString, IsUUID, MaxLength, ValidateIf } from 'class-validator';

/** Estados que puede fijar un usuario en el ciclo de vida y remediación del hallazgo. */
export const REVIEWABLE_STATUSES = [
  FindingStatus.OPEN,
  FindingStatus.IN_PROGRESS,
  FindingStatus.VERIFYING,
  FindingStatus.ACCEPTED,
  FindingStatus.FALSE_POSITIVE,
] as const;

export class ReviewFindingDto {
  @ApiPropertyOptional({ enum: REVIEWABLE_STATUSES, example: FindingStatus.IN_PROGRESS })
  @IsOptional()
  @IsIn(REVIEWABLE_STATUSES)
  status?: (typeof REVIEWABLE_STATUSES)[number];

  @ApiPropertyOptional({ example: 'Puerto necesario para el proveedor de pagos; acceso restringido por firewall.' })
  @IsOptional()
  @IsString()
  @MaxLength(2000)
  note?: string;

  @ApiPropertyOptional({ example: 'b5a036c0-6718-4720-94d7-e23f0ce25d36', description: 'ID del usuario asignado para remediación (null para desasignar)' })
  @IsOptional()
  @ValidateIf((_, val) => val !== null && val !== undefined)
  @IsUUID()
  assignedToId?: string | null;

  @ApiPropertyOptional({ example: '2026-10-15T00:00:00.000Z', description: 'Fecha límite de remediación / SLA (null para limpiar)' })
  @IsOptional()
  @ValidateIf((_, val) => val !== null && val !== undefined)
  @IsISO8601()
  dueDate?: string | null;

  @ApiPropertyOptional({ example: 'Se aplicó parche y se cerró puerto en firewall.' })
  @IsOptional()
  @ValidateIf((_, val) => val !== null && val !== undefined)
  @IsString()
  @MaxLength(2000)
  remediationNote?: string | null;
}

