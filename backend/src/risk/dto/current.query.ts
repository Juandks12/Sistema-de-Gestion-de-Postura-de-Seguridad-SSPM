import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsUUID } from 'class-validator';

export class CurrentScoreQuery {
  @ApiPropertyOptional({ description: 'Score de un activo; si se omite, de la organización' })
  @IsOptional()
  @IsUUID()
  assetId?: string;
}
