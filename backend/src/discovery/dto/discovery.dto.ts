import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArrayMaxSize, ArrayMinSize, ArrayUnique, Equals, IsBoolean, IsOptional, IsUUID } from 'class-validator';

export class UpdateDiscoveredHostDto {
  @ApiProperty({ description: 'true para descartarlo (no se incorporará al inventario), false para restaurarlo.' })
  @IsBoolean()
  ignored!: boolean;
}

export class ImportDiscoveredHostsDto {
  @ApiProperty({ type: [String], description: 'Subdominios descubiertos que se registran como activos (máx. 50).' })
  @ArrayMinSize(1)
  @ArrayMaxSize(50)
  @ArrayUnique()
  @IsUUID('4', { each: true })
  ids!: string[];

  @ApiProperty({ example: true, description: 'Confirmación de que la organización está autorizada a analizarlos (sección 1.6.3).' })
  @IsBoolean()
  @Equals(true, { message: 'Debes confirmar que tienes autorización para analizar estos activos' })
  authorizationConfirmed!: boolean;

  @ApiPropertyOptional({
    example: true,
    description: 'Si es true, lanza automáticamente un lote de Diagnóstico 360° (COMMERCE_360) para cada subdominio que herede verificación.',
  })
  @IsOptional()
  @IsBoolean()
  launchDiagnostic360?: boolean;
}
