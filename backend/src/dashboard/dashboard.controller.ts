import { Controller, Get, Param, ParseIntPipe, ParseUUIDPipe, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { DashboardService } from './dashboard.service';

@ApiTags('dashboard')
@ApiBearerAuth()
@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboard: DashboardService) {}

  @Get('overview')
  @ApiOperation({ summary: 'Vista general: Security Score, tendencia, hallazgos, activos y escaneos recientes' })
  overview(@CurrentUser() user: AuthUser) {
    return this.dashboard.overview(user.organizationId);
  }

  @Get('assets')
  @ApiOperation({ summary: 'Tabla de activos con score, hallazgos abiertos y último escaneo, peor postura primero' })
  assets(@CurrentUser() user: AuthUser) {
    return this.dashboard.assets(user.organizationId);
  }

  @Get('assets/:id')
  @ApiOperation({ summary: 'Vista detallada de un activo: score, histórico, hallazgos y superficie expuesta' })
  asset(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.dashboard.asset(user.organizationId, id);
  }

  @Get('history')
  @ApiOperation({ summary: 'Serie histórica del Security Score de la organización para la gráfica de postura' })
  @ApiQuery({ name: 'days', required: false, description: 'Días hacia atrás (1-365, por defecto 30)' })
  history(@CurrentUser() user: AuthUser, @Query('days', new ParseIntPipe({ optional: true })) days?: number) {
    const bounded = Math.min(365, Math.max(1, days ?? 30));
    return this.dashboard.history(user.organizationId, bounded);
  }
}
