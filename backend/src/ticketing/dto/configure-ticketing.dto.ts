import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { TicketingAutoCreateThreshold, TicketingProvider } from '@prisma/client';
import { IsBoolean, IsEnum, IsNotEmpty, IsObject, IsOptional, IsString, IsUrl } from 'class-validator';

export class ConfigureTicketingDto {
  @ApiProperty({ enum: TicketingProvider, description: 'Proveedor de ticketing (JIRA o AZURE_BOARDS)' })
  @IsEnum(TicketingProvider)
  provider!: TicketingProvider;

  @ApiPropertyOptional({ description: 'Habilitar o pausar la integración', default: true })
  @IsOptional()
  @IsBoolean()
  enabled?: boolean;

  @ApiProperty({
    description: 'URL de la instancia (ej. https://myorg.atlassian.net o https://dev.azure.com/myorg)',
    example: 'https://miempresa.atlassian.net',
  })
  @IsString()
  @IsNotEmpty()
  @IsUrl({ require_tld: false })
  instanceUrl!: string;

  @ApiProperty({
    description: 'Clave de proyecto en Jira (ej. "SEC") o nombre en Azure DevOps (ej. "DevOps - SRE")',
    example: 'SEC',
  })
  @IsString()
  @IsNotEmpty()
  projectKey!: string;

  @ApiPropertyOptional({
    description: 'Tipo de issue o work item por defecto (ej. "Bug", "Task", "Issue")',
    default: 'Bug',
  })
  @IsOptional()
  @IsString()
  issueType?: string;

  @ApiPropertyOptional({
    enum: TicketingAutoCreateThreshold,
    description: 'Umbral de severidad mínima para creación automática tras escaneos',
    default: TicketingAutoCreateThreshold.DISABLED,
  })
  @IsOptional()
  @IsEnum(TicketingAutoCreateThreshold)
  autoCreateThreshold?: TicketingAutoCreateThreshold;

  @ApiProperty({
    description: 'Credenciales del servicio: para Jira { email, apiToken }; para Azure Boards { personalAccessToken }',
  })
  @IsObject()
  @IsNotEmpty()
  credentials!: Record<string, string>;

  @ApiPropertyOptional({ description: 'Configuración adicional (etiquetas por defecto, mapeos)' })
  @IsOptional()
  @IsObject()
  config?: Record<string, unknown>;
}
