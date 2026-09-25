import { Controller, Get, HttpCode, HttpStatus, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { CurrentScoreQuery } from './dto/current.query';
import { HistoryQuery } from './dto/history.query';
import { RiskScoresService } from './risk-scores.service';
import { describeModel } from './scoring';

@ApiTags('risk-scores')
@ApiBearerAuth()
@Controller('risk-scores')
export class RiskScoresController {
  constructor(private readonly riskScores: RiskScoresService) {}

  @Get('current')
  @ApiOperation({ summary: 'RF-07: Security Score actual con el desglose de la fórmula' })
  current(@CurrentUser() user: AuthUser, @Query() query: CurrentScoreQuery) {
    return this.riskScores.current(user.organizationId, query.assetId);
  }

  @Get('history')
  @ApiOperation({ summary: 'RF-11: histórico de postura de la organización o de un activo' })
  history(@CurrentUser() user: AuthUser, @Query() query: HistoryQuery) {
    return this.riskScores.history(user.organizationId, query);
  }

  @Get('model')
  @ApiOperation({ summary: 'Modelo de puntuación: fórmula, pesos, topes y calificaciones' })
  model() {
    return describeModel();
  }

  @Post('recalculate')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Recalcular y registrar una instantánea de todos los activos y de la organización' })
  recalculate(@CurrentUser() user: AuthUser) {
    return this.riskScores.recalculate(user.organizationId);
  }
}
