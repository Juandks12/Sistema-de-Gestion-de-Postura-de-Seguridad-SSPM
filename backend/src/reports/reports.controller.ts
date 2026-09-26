import { Controller, Get, Query, StreamableFile } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiProduces, ApiQuery, ApiTags } from '@nestjs/swagger';
import { ReportType } from '@prisma/client';
import { IsOptional, IsUUID } from 'class-validator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ReportsService } from './reports.service';

class ReportQuery {
  @IsOptional()
  @IsUUID()
  assetId?: string;
}

/** Todos los roles pueden descargar reportes: la gerencia (VIEWER) es su destinatario principal. */
@ApiTags('reports')
@ApiBearerAuth()
@Controller('reports')
export class ReportsController {
  constructor(private readonly reports: ReportsService) {}

  @Get()
  @ApiOperation({ summary: 'Historial de reportes generados en la organización' })
  list(@CurrentUser() user: AuthUser) {
    return this.reports.list(user.organizationId);
  }

  @Get('executive')
  @ApiProduces('application/pdf')
  @ApiQuery({ name: 'assetId', required: false, description: 'Reporte de un solo activo; si se omite, de toda la organización' })
  @ApiOperation({ summary: 'RF-09: reporte ejecutivo en PDF (score, tendencia, principales riesgos y recomendaciones)' })
  async executive(@CurrentUser() user: AuthUser, @Query() query: ReportQuery) {
    const report = await this.reports.generate(user, ReportType.EXECUTIVE, query.assetId);
    return new StreamableFile(report.buffer, {
      type: 'application/pdf',
      disposition: `attachment; filename="${report.filename}"`,
      length: report.buffer.length,
    });
  }

  @Get('technical')
  @ApiProduces('application/pdf')
  @ApiQuery({ name: 'assetId', required: false, description: 'Reporte de un solo activo; si se omite, de toda la organización' })
  @ApiOperation({ summary: 'RF-09: reporte técnico en PDF (puertos, hallazgos, evidencia y recomendaciones por activo)' })
  async technical(@CurrentUser() user: AuthUser, @Query() query: ReportQuery) {
    const report = await this.reports.generate(user, ReportType.TECHNICAL, query.assetId);
    return new StreamableFile(report.buffer, {
      type: 'application/pdf',
      disposition: `attachment; filename="${report.filename}"`,
      length: report.buffer.length,
    });
  }
}
