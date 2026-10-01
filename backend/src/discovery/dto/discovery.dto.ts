import { ApiProperty } from '@nestjs/swagger';
import { ArrayMaxSize, ArrayMinSize, ArrayUnique, Equals, IsBoolean, IsUUID } from 'class-validator';

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
}
