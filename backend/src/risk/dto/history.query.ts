import { ApiPropertyOptional } from '@nestjs/swagger';
import { Type } from 'class-transformer';
import { IsDate, IsIn, IsOptional, IsUUID } from 'class-validator';

export class HistoryQuery {
  @ApiPropertyOptional({ description: 'Histórico de un activo; si se omite, de la organización' })
  @IsOptional()
  @IsUUID()
  assetId?: string;

  @ApiPropertyOptional({ example: '2026-09-01T00:00:00Z' })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  from?: Date;

  @ApiPropertyOptional({ example: '2026-09-30T23:59:59Z' })
  @IsOptional()
  @Type(() => Date)
  @IsDate()
  to?: Date;

  @ApiPropertyOptional({
    enum: ['day', 'raw'],
    default: 'day',
    description: '`day` conserva la última instantánea de cada día; `raw` devuelve todas',
  })
  @IsOptional()
  @IsIn(['day', 'raw'])
  granularity: 'day' | 'raw' = 'day';
}
