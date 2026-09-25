import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { IsOptional, IsUUID } from 'class-validator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
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
}
