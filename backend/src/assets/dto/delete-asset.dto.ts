import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength } from 'class-validator';

export class DeleteAssetDto {
  @ApiPropertyOptional({
    description: 'Motivo o justificación de la eliminación del activo para el registro de auditoría',
    example: 'Servidor desmantelado y migrado al nuevo cluster de Kubernetes',
  })
  @IsOptional()
  @IsString()
  @MaxLength(500)
  reason?: string;
}
