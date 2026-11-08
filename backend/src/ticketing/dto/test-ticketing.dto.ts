import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { TicketingProvider } from '@prisma/client';
import { IsEnum, IsNotEmpty, IsObject, IsOptional, IsString, IsUrl } from 'class-validator';

export class TestTicketingDto {
  @ApiProperty({ enum: TicketingProvider, description: 'Proveedor a probar (JIRA o AZURE_BOARDS)' })
  @IsEnum(TicketingProvider)
  provider!: TicketingProvider;

  @ApiProperty({
    description: 'URL de la instancia',
    example: 'https://miempresa.atlassian.net',
  })
  @IsString()
  @IsNotEmpty()
  @IsUrl({ require_tld: false })
  instanceUrl!: string;

  @ApiProperty({
    description: 'Clave de proyecto o nombre de proyecto',
    example: 'SEC',
  })
  @IsString()
  @IsNotEmpty()
  projectKey!: string;

  @ApiPropertyOptional({
    description: 'Credenciales en claro para la prueba. Si se omite, se intentan usar las credenciales guardadas de la organización.',
  })
  @IsOptional()
  @IsObject()
  credentials?: Record<string, string>;
}
