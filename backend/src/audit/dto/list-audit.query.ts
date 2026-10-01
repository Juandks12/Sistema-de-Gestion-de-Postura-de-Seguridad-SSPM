import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsIn, IsISO8601, IsInt, IsOptional, IsUUID, Max, Min } from 'class-validator';
import { AUDIT_ACTIONS } from '../audit-actions';

export class ListAuditQuery {
  @ApiPropertyOptional({ description: 'Acción del catálogo, p. ej. user.create' })
  @IsOptional()
  @IsIn(Object.keys(AUDIT_ACTIONS))
  action?: keyof typeof AUDIT_ACTIONS;

  @ApiPropertyOptional({ description: 'Filtrar por el usuario que realizó la acción' })
  @IsOptional()
  @IsUUID()
  actorId?: string;

  @ApiPropertyOptional({ description: 'Desde (ISO 8601)' })
  @IsOptional()
  @IsISO8601()
  from?: string;

  @ApiPropertyOptional({ description: 'Hasta (ISO 8601)' })
  @IsOptional()
  @IsISO8601()
  to?: string;

  @ApiPropertyOptional({ default: 1 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  page: number = 1;

  @ApiPropertyOptional({ default: 25, maximum: 100 })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(100)
  pageSize: number = 25;
}
