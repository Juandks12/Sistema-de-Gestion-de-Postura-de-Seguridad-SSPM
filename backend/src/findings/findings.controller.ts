import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post, Query, StreamableFile } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiProduces, ApiQuery, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { IsOptional, IsUUID } from 'class-validator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ExportFindingsQuery } from './dto/export-findings.query';
import { ListFindingsQuery } from './dto/list-findings.query';
import { ReviewFindingDto } from './dto/review-finding.dto';
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
  constructor(private readonly findings: FindingsService) {}

  @Get()
  @ApiOperation({ summary: 'RF-08: listar hallazgos de mi organización, ordenados por severidad' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListFindingsQuery) {
    return this.findings.findAll(user.organizationId, query);
  }

  @Get('summary')
  @ApiOperation({ summary: 'Conteo de hallazgos abiertos por severidad y categoría' })
  @ApiQuery({ name: 'assetId', required: false })
  summary(@CurrentUser() user: AuthUser, @Query() query: SummaryQuery) {
    return this.findings.summary(user.organizationId, query.assetId);
  }

  @Get('rules')
  @ApiOperation({ summary: 'Catálogo de reglas de hallazgos con su severidad y CVSS de referencia' })
  rules() {
    return [...FINDING_RULES.values()];
  }

  @Get('export')
  @ApiProduces('text/csv')
  @ApiOperation({ summary: 'Exportar hallazgos a formato CSV con soporte de streaming y filtros' })
  export(@CurrentUser() user: AuthUser, @Query() query: ExportFindingsQuery) {
    const filename = `findings-${new Date().toISOString().slice(0, 10)}.csv`;
    const stream = this.findings.exportStream(user.organizationId, query);
    return new StreamableFile(stream, {
      type: 'text/csv; charset=utf-8',
      disposition: `attachment; filename="${filename}"`,
    });
  }

  @Get(':id')
  @ApiOperation({ summary: 'Detalle de un hallazgo' })
  findOne(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.findings.findOne(user.organizationId, id);
  }

  @Patch(':id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Aceptar el riesgo, marcar como falso positivo o reabrir un hallazgo' })
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
