import {
  BadRequestException,
  Controller,
  Get,
  Param,
  Query,
  StreamableFile,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiProduces,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ComplianceFramework } from './compliance.catalog';
import { ComplianceService } from './compliance.service';

@ApiTags('compliance')
@ApiBearerAuth()
@Controller('compliance')
export class ComplianceController {
  constructor(private readonly complianceService: ComplianceService) {}

  @Get()
  @ApiOperation({ summary: 'Obtener resumen general de cumplimiento en todos los marcos normativos' })
  getOverview(@CurrentUser() user: AuthUser) {
    return this.complianceService.getOverview(user.organizationId);
  }

  @Get('frameworks/:framework')
  @ApiOperation({ summary: 'Obtener detalle de controles y hallazgos asociados para un marco específico' })
  @ApiParam({ name: 'framework', enum: ComplianceFramework })
  getFrameworkDetails(
    @CurrentUser() user: AuthUser,
    @Param('framework') framework: string,
  ) {
    const fw = framework.toUpperCase() as ComplianceFramework;
    if (!Object.values(ComplianceFramework).includes(fw)) {
      throw new BadRequestException(
        `Marco regulatorio inválido: ${framework}. Valores permitidos: ${Object.values(ComplianceFramework).join(', ')}`,
      );
    }
    return this.complianceService.getFrameworkDetails(user.organizationId, fw);
  }

  @Get('export')
  @ApiProduces('text/csv')
  @ApiOperation({ summary: 'Exportar matriz de cumplimiento a formato CSV' })
  @ApiQuery({ name: 'framework', enum: ComplianceFramework })
  async export(
    @CurrentUser() user: AuthUser,
    @Query('framework') framework: string,
  ) {
    const fw = (framework || '').toUpperCase() as ComplianceFramework;
    if (!Object.values(ComplianceFramework).includes(fw)) {
      throw new BadRequestException(
        `Marco regulatorio inválido: ${framework}. Valores permitidos: ${Object.values(ComplianceFramework).join(', ')}`,
      );
    }
    const csv = await this.complianceService.exportCsv(user.organizationId, fw);
    const filename = `compliance-${fw.toLowerCase().replace(/_/g, '-')}-${new Date().toISOString().slice(0, 10)}.csv`;
    return new StreamableFile(Buffer.from(csv, 'utf-8'), {
      type: 'text/csv; charset=utf-8',
      disposition: `attachment; filename="${filename}"`,
    });
  }
}
