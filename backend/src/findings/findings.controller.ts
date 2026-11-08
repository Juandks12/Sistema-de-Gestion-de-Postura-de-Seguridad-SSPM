import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post, Query, StreamableFile } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiProduces, ApiQuery, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { IsOptional, IsUUID } from 'class-validator';
import { COMPLIANCE_CONTROLS, FRAMEWORKS_METADATA } from '../compliance/compliance.catalog';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { BulkReviewFindingsDto } from './dto/bulk-review-findings.dto';
import { CreateManualFindingDto } from './dto/create-manual-finding.dto';
import { ExportFindingsQuery } from './dto/export-findings.query';
import { ListFindingsQuery } from './dto/list-findings.query';
import { ReviewFindingDto } from './dto/review-finding.dto';
import { AttackPathsService } from './attack-paths.service';
import { FindingTriageService } from './finding-triage.service';
import { FindingsService } from './findings.service';
import { FINDING_RULES } from './rules.catalog';

class SummaryQuery {
  @IsOptional()
  @IsUUID()
  assetId?: string;
}

@ApiTags('findings')
@ApiBearerAuth()
@Controller('findings')
export class FindingsController {
  constructor(
    private readonly findings: FindingsService,
    private readonly triageService: FindingTriageService,
    private readonly attackPathsService: AttackPathsService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'RF-08: listar hallazgos de mi organización en el Centro Maestro (GRC Hub)' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListFindingsQuery) {
    return this.findings.findAll(user.organizationId, query);
  }

  @Get('summary')
  @ApiOperation({ summary: 'Conteo de hallazgos abiertos por severidad, categoría, origen, SLA y marco normativo' })
  @ApiQuery({ name: 'assetId', required: false })
  summary(@CurrentUser() user: AuthUser, @Query() query: SummaryQuery) {
    return this.findings.summary(user.organizationId, query.assetId);
  }

  @Get('attack-paths')
  @ApiOperation({ summary: 'Correlación de rutas de ataque y escenarios de riesgo compuesto' })
  @ApiQuery({ name: 'assetId', required: false })
  attackPaths(@CurrentUser() user: AuthUser, @Query() query: SummaryQuery) {
    return this.attackPathsService.analyzeAttackPaths(user.organizationId, query.assetId);
  }

  @Get('rules')
  @ApiOperation({ summary: 'Catálogo de reglas de hallazgos con su severidad y CVSS de referencia' })
  rules() {
    return [...FINDING_RULES.values()];
  }

  @Get('grc-catalog')
  @ApiOperation({ summary: 'Catálogo de marcos normativos y controles (ISO 27001, PCI-DSS, NIST, CIS, SOC 2) para mapeo de hallazgos' })
  grcCatalog() {
    return {
      frameworks: Object.values(FRAMEWORKS_METADATA),
      controls: COMPLIANCE_CONTROLS.map((c) => ({
        id: c.id,
        framework: c.framework,
        frameworkName: FRAMEWORKS_METADATA[c.framework]?.name ?? c.framework,
        code: c.code,
        title: c.title,
        domain: c.domain,
      })),
    };
  }

  @Get('export')
  @ApiProduces('text/csv')
  @ApiOperation({ summary: 'Exportar matriz completa de hallazgos y controles GRC a formato CSV con streaming' })
  export(@CurrentUser() user: AuthUser, @Query() query: ExportFindingsQuery) {
    const filename = `findings-${new Date().toISOString().slice(0, 10)}.csv`;
    const stream = this.findings.exportStream(user.organizationId, query);
    return new StreamableFile(stream, {
      type: 'text/csv; charset=utf-8',
      disposition: `attachment; filename="${filename}"`,
    });
  }

  @Post('manual')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Registrar un hallazgo de seguridad general o de auditoría manual / pentesting' })
  createManual(@CurrentUser() user: AuthUser, @Body() dto: CreateManualFindingDto) {
    return this.findings.createManual(user, dto);
  }

  @Patch('bulk')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Triage masivo en lote: actualizar estado, responsable, fecha límite SLA y notas para múltiples hallazgos' })
  bulkReview(@CurrentUser() user: AuthUser, @Body() dto: BulkReviewFindingsDto) {
    return this.findings.bulkReview(user, dto);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Detalle de un hallazgo con ficha técnica y normativa completa' })
  findOne(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.findings.findOne(user.organizationId, id);
  }

  @Get(':id/remediation')
  @ApiOperation({ summary: 'Obtener guía de remediación interactiva y snippets técnicos de configuración' })
  remediation(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.findings.getRemediation(user.organizationId, id);
  }

  @Get(':id/triage')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Triage asistido por IA / motor experto para evaluación de falso positivo' })
  @ApiQuery({ name: 'refresh', required: false, description: 'Fuerza la regeneración del análisis evitando la caché' })
  triage(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Query('refresh') refresh?: string,
  ) {
    return this.triageService.analyze(user.organizationId, id, refresh === 'true');
  }

  @Patch(':id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Aceptar el riesgo, marcar como falso positivo, asignar responsable o reabrir un hallazgo' })
  review(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: ReviewFindingDto,
  ) {
    return this.findings.review(user, id, dto);
  }

  @Post(':id/retest')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Re-test puntual de un hallazgo para comprobar si ya ha sido remediado' })
  retest(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.findings.retest(user, id);
  }
}
