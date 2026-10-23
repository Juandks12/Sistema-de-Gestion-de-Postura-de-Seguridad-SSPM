import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { DiagnosticOrchestratorService } from './diagnostic-orchestrator.service';
import { PostureDiffQuery, StartDiagnosticDto } from './dto/diagnostic-360.dto';

@ApiTags('diagnostic-360')
@ApiBearerAuth()
@Controller()
export class DiagnosticController {
  constructor(private readonly orchestrator: DiagnosticOrchestratorService) {}

  @Post('assets/:assetId/diagnostic-360')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Iniciar Diagnóstico Integral 360° multi-etapa encadenado',
    description:
      'Coordina un pipeline de 3 etapas secuenciales: Descubrimiento de Superficie -> Perímetro y Puertos -> Web Profunda y E-Commerce.',
  })
  @ApiResponse({ status: 202, description: 'Lote de Diagnóstico 360° encolado y en progreso.' })
  @ApiResponse({ status: 409, description: 'Ya existe un Diagnóstico 360° activo para este activo.' })
  start(
    @CurrentUser() user: AuthUser,
    @Param('assetId', ParseUUIDPipe) assetId: string,
    @Body() dto: StartDiagnosticDto,
  ) {
    return this.orchestrator.start(user, assetId, dto.profile);
  }

  @Get('assets/:assetId/diagnostic-360/latest')
  @ApiOperation({
    summary: 'Obtener el Diagnóstico Integral 360° más reciente de un activo',
  })
  @ApiResponse({ status: 200, description: 'Detalle y progreso de las 3 etapas del diagnóstico.' })
  getLatest(
    @CurrentUser() user: AuthUser,
    @Param('assetId', ParseUUIDPipe) assetId: string,
  ) {
    return this.orchestrator.getLatestBatchForAsset(user.organizationId, assetId);
  }

  @Get('assets/:assetId/diagnostic-360/:batchId')
  @ApiOperation({
    summary: 'Obtener el estado, métricas y etapas de un lote de Diagnóstico 360° específico',
  })
  @ApiResponse({ status: 200, description: 'Detalle del lote, etapas y porcentaje de avance.' })
  getBatch(
    @CurrentUser() user: AuthUser,
    @Param('batchId', ParseUUIDPipe) batchId: string,
  ) {
    return this.orchestrator.getBatch(user.organizationId, batchId);
  }

  @Get('assets/:assetId/posture-diff')
  @ApiOperation({
    summary: 'Obtener comparativa temporal de postura (Diff) entre diagnósticos',
    description:
      'Compara la postura de seguridad entre dos auditorías: variación de score, hallazgos remediados vs. nuevas regresiones y cambios de superficie.',
  })
  @ApiResponse({ status: 200, description: 'Comparativa temporal estructurada.' })
  getPostureDiff(
    @CurrentUser() user: AuthUser,
    @Param('assetId', ParseUUIDPipe) assetId: string,
    @Query() query: PostureDiffQuery,
  ) {
    return this.orchestrator.getPostureDiff(
      user.organizationId,
      assetId,
      query.fromBatchId,
      query.toBatchId,
    );
  }

  @Post('assets/:assetId/diagnostic-360/:batchId/cancel')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'Cancelar un lote de Diagnóstico 360° en progreso',
  })
  @ApiResponse({ status: 200, description: 'Lote y escaneos asociados cancelados.' })
  cancel(
    @CurrentUser() user: AuthUser,
    @Param('batchId', ParseUUIDPipe) batchId: string,
  ) {
    return this.orchestrator.cancelBatch(user.organizationId, batchId);
  }
}
