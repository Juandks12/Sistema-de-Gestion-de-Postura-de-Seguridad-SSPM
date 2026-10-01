import { Controller, Get, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AUDIT_ACTIONS } from './audit-actions';
import { AuditService } from './audit.service';
import { ListAuditQuery } from './dto/list-audit.query';

@ApiTags('audit')
@ApiBearerAuth()
@Roles(UserRole.ADMIN)
@Controller('audit-log')
export class AuditController {
  constructor(private readonly audit: AuditService) {}

  @Get()
  @ApiOperation({ summary: 'RNF-06: registro de auditoría de la organización (solo ADMIN)' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListAuditQuery) {
    return this.audit.findAll(user.organizationId, query);
  }

  @Get('actions')
  @ApiOperation({ summary: 'Catálogo de acciones auditadas, con su etiqueta' })
  actions() {
    return { actions: AUDIT_ACTIONS };
  }
}
