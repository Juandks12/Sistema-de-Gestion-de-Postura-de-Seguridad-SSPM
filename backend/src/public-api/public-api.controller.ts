import { Controller, Get, Headers, Query, UseGuards } from '@nestjs/common';
import { ApiHeader, ApiOperation, ApiProduces, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CurrentOrgId, RequireApiKeyScope } from '../api-keys/api-key-auth.decorator';
import { PublicApiKeyGuard } from '../api-keys/public-api-key.guard';
import { Public } from '../common/decorators/public.decorator';
import {
  PublicAlertsQueryDto,
  PublicAssetsQueryDto,
  PublicAttackPathsQueryDto,
  PublicComplianceQueryDto,
  PublicFindingsQueryDto,
  PublicThreatLabQueryDto,
} from './dto/public-query.dto';
import { toNdjsonStream } from './ndjson.util';
import { PublicApiService } from './public-api.service';

@ApiTags('public')
@ApiHeader({
  name: 'X-API-Key',
  description: 'Llave de API en formato sspm_live_... (o mediante encabezado Authorization: Bearer sspm_live_...)',
  required: true,
})
@Public()
@UseGuards(PublicApiKeyGuard)
@Controller('public')
export class PublicApiController {
  constructor(private readonly publicApi: PublicApiService) {}

  @Get('findings')
  @RequireApiKeyScope('findings:read')
  @ApiOperation({
    summary: 'Exportar hallazgos de seguridad para ingesta SIEM (Splunk, Wazuh, Elastic, Datadog)',
    description: 'Permite consultar incrementalmente mediante el parámetro `since` y soporta formatos JSON y NDJSON.',
  })
  @ApiProduces('application/json', 'application/x-ndjson')
  @ApiResponse({ status: 200, description: 'Listado de hallazgos en formato JSON o NDJSON' })
  async getFindings(
    @CurrentOrgId() orgId: string,
    @Query() query: PublicFindingsQueryDto,
    @Headers('accept') acceptHeader?: string,
  ) {
    const result = await this.publicApi.getFindings(orgId, query);
    if (query.format === 'ndjson' || acceptHeader?.includes('application/x-ndjson')) {
      return toNdjsonStream(result.items);
    }
    return result;
  }

  @Get('alerts')
  @RequireApiKeyScope('alerts:read')
  @ApiOperation({
    summary: 'Exportar alertas de seguridad para sistemas SIEM/SOAR',
    description: 'Retorna alertas de seguridad generadas con soporte de cursor incremental y formato NDJSON.',
  })
  @ApiProduces('application/json', 'application/x-ndjson')
  @ApiResponse({ status: 200, description: 'Listado de alertas en formato JSON o NDJSON' })
  async getAlerts(
    @CurrentOrgId() orgId: string,
    @Query() query: PublicAlertsQueryDto,
    @Headers('accept') acceptHeader?: string,
  ) {
    const result = await this.publicApi.getAlerts(orgId, query);
    if (query.format === 'ndjson' || acceptHeader?.includes('application/x-ndjson')) {
      return toNdjsonStream(result.items);
    }
    return result;
  }

  @Get('posture')
  @RequireApiKeyScope('posture:read')
  @ApiOperation({
    summary: 'Consultar métricas y calificación de postura de seguridad global',
    description: 'Devuelve la última instantánea de postura calculada, calificación (A+, A, B...), desglose de penalizaciones y resumen de hallazgos.',
  })
  @ApiResponse({ status: 200, description: 'Postura global de la organización' })
  async getPosture(@CurrentOrgId() orgId: string) {
    return this.publicApi.getPosture(orgId);
  }

  @Get('assets')
  @RequireApiKeyScope('assets:read')
  @ApiOperation({
    summary: 'Exportar inventario de activos externos y su criticidad',
    description: 'Retorna dominios e IPs autorizados junto con su estado de verificación y recuento de hallazgos abiertos.',
  })
  @ApiProduces('application/json', 'application/x-ndjson')
  @ApiResponse({ status: 200, description: 'Inventario de activos' })
  async getAssets(
    @CurrentOrgId() orgId: string,
    @Query() query: PublicAssetsQueryDto,
    @Headers('accept') acceptHeader?: string,
  ) {
    const result = await this.publicApi.getAssets(orgId, query);
    if (query.format === 'ndjson' || acceptHeader?.includes('application/x-ndjson')) {
      return toNdjsonStream(result.items);
    }
    return result;
  }

  @Get('attack-paths')
  @RequireApiKeyScope('findings:read')
  @ApiOperation({
    summary: 'Exportar rutas de ataque correlacionadas (Kill-Chains) para sistemas SIEM/SOAR',
    description: 'Retorna escenarios activos de compromiso correlacionados entre vectores perimetrales, e-commerce y cloud.',
  })
  @ApiProduces('application/json', 'application/x-ndjson')
  @ApiResponse({ status: 200, description: 'Rutas de ataque activas en formato JSON o NDJSON' })
  async getAttackPaths(
    @CurrentOrgId() orgId: string,
    @Query() query: PublicAttackPathsQueryDto,
    @Headers('accept') acceptHeader?: string,
  ) {
    const result = await this.publicApi.getAttackPaths(orgId, query);
    if (query.format === 'ndjson' || acceptHeader?.includes('application/x-ndjson')) {
      return toNdjsonStream(result.items);
    }
    return result;
  }

  @Get('compliance')
  @RequireApiKeyScope('posture:read')
  @ApiOperation({
    summary: 'Exportar matriz de cumplimiento normativo GRC (ISO 27001, PCI-DSS v4.0, NIST CSF 2.0, CIS v8, SOC 2)',
    description: 'Retorna el resumen global de cumplimiento normativo y, opcionalmente, el desglose de controles de un estándar.',
  })
  @ApiResponse({ status: 200, description: 'Postura de cumplimiento normativo GRC' })
  async getCompliance(
    @CurrentOrgId() orgId: string,
    @Query() query: PublicComplianceQueryDto,
  ) {
    return this.publicApi.getCompliance(orgId, query);
  }

  @Get('threat-lab')
  @RequireApiKeyScope('findings:read')
  @ApiOperation({
    summary: 'Exportar análisis forenses e IoCs del Laboratorio de Malware y Phishing',
    description: 'Retorna correos .eml, archivos/hashes SHA-256 y URLs analizadas junto con sus indicadores MITRE ATT&CK y veredictos.',
  })
  @ApiProduces('application/json', 'application/x-ndjson')
  @ApiResponse({ status: 200, description: 'Listado de análisis del Threat Lab en formato JSON o NDJSON' })
  async getThreatLab(
    @CurrentOrgId() orgId: string,
    @Query() query: PublicThreatLabQueryDto,
    @Headers('accept') acceptHeader?: string,
  ) {
    const result = await this.publicApi.getThreatLab(orgId, query);
    if (query.format === 'ndjson' || acceptHeader?.includes('application/x-ndjson')) {
      return toNdjsonStream(result.items);
    }
    return result;
  }
}
