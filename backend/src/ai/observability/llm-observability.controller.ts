import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthUser } from '../../common/interfaces/auth-user.interface';
import { LlmObservabilityService } from './llm-observability.service';

@Controller('ai/observability')
@UseGuards(JwtAuthGuard, RolesGuard)
export class LlmObservabilityController {
  constructor(private readonly observabilityService: LlmObservabilityService) {}

  @Get('stats')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async getStats(
    @CurrentUser() user: AuthUser,
    @Query('days') days?: string,
  ) {
    const numDays = days ? parseInt(days, 10) : 30;
    return this.observabilityService.getStats(user.organizationId, numDays);
  }

  @Get('logs')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  async getRecentLogs(
    @CurrentUser() user: AuthUser,
    @Query('limit') limit?: string,
  ) {
    const numLimit = limit ? parseInt(limit, 10) : 20;
    return this.observabilityService.getRecentLogs(user.organizationId, numLimit);
  }
}
