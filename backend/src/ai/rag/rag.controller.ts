import { Body, Controller, Get, Param, ParseUUIDPipe, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { UserRole } from '@prisma/client';
import { RagRetrievalService } from './rag-retrieval.service';
import { KnowledgeIngestionService } from './knowledge-ingestion.service';
import { RagSearchDto } from './dto/rag-search.dto';
import { RemediationAdviceDto } from './dto/remediation-advice.dto';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthUser } from '../../common/interfaces/auth-user.interface';

@Controller('ai/rag')
@UseGuards(JwtAuthGuard, RolesGuard)
export class RagController {
  constructor(
    private readonly ragRetrievalService: RagRetrievalService,
    private readonly ingestionService: KnowledgeIngestionService,
  ) {}

  @Post('search')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  async search(@Body() dto: RagSearchDto) {
    return this.ragRetrievalService.searchSemantic(dto);
  }

  @Post('remediation-advice/:findingId')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  async getRemediationAdvice(
    @Param('findingId', ParseUUIDPipe) findingId: string,
    @Body() dto: RemediationAdviceDto,
    @CurrentUser() user: AuthUser,
  ) {
    return this.ragRetrievalService.generateRemediationAdvice(
      findingId,
      user.organizationId,
      dto.customContext,
    );
  }

  @Post('ingest')
  @Roles(UserRole.ADMIN)
  async triggerIngestion() {
    return this.ingestionService.syncKnowledgeBase();
  }

  @Get('stats')
  @Roles(UserRole.ADMIN, UserRole.ANALYST, UserRole.VIEWER)
  async getStats() {
    return this.ingestionService.getStats();
  }
}

