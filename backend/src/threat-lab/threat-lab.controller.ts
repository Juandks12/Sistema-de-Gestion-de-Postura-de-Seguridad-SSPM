import { Body, Controller, Get, Param, ParseUUIDPipe, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import {
  AnalyzeEmailDto,
  AnalyzeFileDto,
  AnalyzeUrlDto,
  ListMalwareAnalysesQuery,
  PromoteAnalysisToFindingDto,
} from './dto/threat-lab.dto';
import { ThreatLabService } from './threat-lab.service';

@ApiTags('threat-lab')
@ApiBearerAuth()
@Controller('threat-lab')
export class ThreatLabController {
  constructor(private readonly threatLab: ThreatLabService) {}

  @Get('summary')
  @ApiOperation({ summary: 'Métricas consolidadas del Laboratorio de Malware y Phishing por tipo de artefacto y veredicto' })
  summary(@CurrentUser() user: AuthUser) {
    return this.threatLab.summary(user.organizationId);
  }

  @Get()
  @ApiOperation({ summary: 'Listar historial paginado de análisis forenses (correos, archivos/hashes y URLs)' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListMalwareAnalysesQuery) {
    return this.threatLab.findAll(user.organizationId, query);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Obtener detalle forense completo de un análisis del Laboratorio de Malware' })
  findOne(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.threatLab.findOne(user.organizationId, id);
  }

  @Post('analyze/email')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Analizar correo electrónico (.eml / cabeceras MIME) contra Phishing, BEC y suplantación SPF/DKIM/DMARC' })
  analyzeEmail(@CurrentUser() user: AuthUser, @Body() dto: AnalyzeEmailDto) {
    return this.threatLab.analyzeEmail(user, dto);
  }

  @Post('analyze/file')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Analizar archivo o hash SHA-256 (Magic Bytes, doble extensión, entropía de Shannon, macros VBA/XLM, PDF /JS y Threat Intel)' })
  analyzeFile(@CurrentUser() user: AuthUser, @Body() dto: AnalyzeFileDto) {
    return this.threatLab.analyzeFile(user, dto);
  }

  @Post('analyze/url')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Analizar URL sospechosa (suplantación de marca, homógrafos IDN, redirecciones y distribución de payloads)' })
  analyzeUrl(@CurrentUser() user: AuthUser, @Body() dto: AnalyzeUrlDto) {
    return this.threatLab.analyzeUrl(user, dto);
  }

  @Post(':id/promote-finding')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Promover un análisis malicioso o sospechoso a un Hallazgo formal en el Centro Maestro de Hallazgos y GRC' })
  promoteToFinding(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: PromoteAnalysisToFindingDto,
  ) {
    return this.threatLab.promoteToFinding(user, id, dto);
  }
}
