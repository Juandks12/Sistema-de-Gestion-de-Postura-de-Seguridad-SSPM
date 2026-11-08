import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';

export class CreateFindingTicketDto {
  @ApiPropertyOptional({ description: 'Notas personalizadas adicionales del analista que se adjuntarán al ticket' })
  @IsOptional()
  @IsString()
  notes?: string;

  @ApiPropertyOptional({ description: 'Sobreescribir tipo de ticket para esta creación específica (opcional)' })
  @IsOptional()
  @IsString()
  issueType?: string;
}
