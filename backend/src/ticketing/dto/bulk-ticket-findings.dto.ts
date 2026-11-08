import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { ArrayNotEmpty, IsArray, IsOptional, IsString, IsUUID } from 'class-validator';

export class BulkTicketFindingsDto {
  @ApiProperty({ description: 'Lista de IDs de hallazgos a convertir en tickets de ingeniería', type: [String] })
  @IsArray()
  @ArrayNotEmpty()
  @IsUUID('4', { each: true })
  findingIds!: string[];

  @ApiPropertyOptional({ description: 'Notas compartidas del analista para los tickets creados' })
  @IsOptional()
  @IsString()
  notes?: string;
}
