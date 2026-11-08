import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, ParseUUIDPipe, Post, Put } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { BulkTicketFindingsDto } from './dto/bulk-ticket-findings.dto';
import { ConfigureTicketingDto } from './dto/configure-ticketing.dto';
import { CreateFindingTicketDto } from './dto/create-finding-ticket.dto';
import { TestTicketingDto } from './dto/test-ticketing.dto';
import { TicketingService } from './ticketing.service';
import { CreatedTicketResult, TestConnectionResult, TicketingConfigSummary } from './ticketing.types';

@ApiTags('ticketing')
@ApiBearerAuth()
@Controller('ticketing')
export class TicketingController {
  constructor(private readonly ticketingService: TicketingService) {}

  @Get('config')
  @ApiOperation({ summary: 'Obtener la configuración activa de integración con Jira o Azure Boards' })
  @ApiResponse({ status: 200, description: 'Resumen de configuración sin credenciales sensibles' })
  async getConfig(@CurrentUser() user: AuthUser): Promise<TicketingConfigSummary | null> {
    return this.ticketingService.getConfig(user.organizationId);
  }

  @Put('config')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Configurar o actualizar la integración con Jira Software o Azure Boards' })
  @ApiResponse({ status: 200, description: 'Configuración guardada exitosamente' })
  async configure(
    @CurrentUser() user: AuthUser,
    @Body() dto: ConfigureTicketingDto,
  ): Promise<TicketingConfigSummary> {
    return this.ticketingService.configureIntegration(user, dto);
  }

  @Post('test')
  @HttpCode(HttpStatus.OK)
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Probar conectividad y permisos con la instancia de Jira o Azure Boards' })
  @ApiResponse({ status: 200, description: 'Resultado de la prueba de conexión y acceso a proyecto' })
  async testConnection(
    @CurrentUser() user: AuthUser,
    @Body() dto: TestTicketingDto,
  ): Promise<TestConnectionResult> {
    return this.ticketingService.testIntegration(user.organizationId, dto);
  }

  @Delete('config')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Eliminar y desvincular la integración de ticketing de la organización' })
  @ApiResponse({ status: 200, description: 'Integración eliminada' })
  async delete(@CurrentUser() user: AuthUser): Promise<{ ok: boolean }> {
    return this.ticketingService.deleteIntegration(user);
  }

  @Post('findings/:id/ticket')
  @ApiOperation({ summary: 'Crear ticket de remediación en Jira o Azure Boards para un hallazgo específico' })
  @ApiResponse({ status: 201, description: 'Ticket creado exitosamente' })
  async createTicket(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) findingId: string,
    @Body() dto: CreateFindingTicketDto,
  ): Promise<CreatedTicketResult> {
    return this.ticketingService.createTicketForFinding(user, findingId, dto);
  }

  @Post('findings/bulk-ticket')
  @ApiOperation({ summary: 'Crear tickets de remediación masivos para una lista de hallazgos' })
  @ApiResponse({ status: 200, description: 'Resumen de tickets creados y errores' })
  async createTicketsBulk(
    @CurrentUser() user: AuthUser,
    @Body() dto: BulkTicketFindingsDto,
  ) {
    return this.ticketingService.createTicketsBulk(user, dto);
  }

  @Post('findings/:id/sync')
  @ApiOperation({ summary: 'Sincronizar bidireccionalmente el estado del ticket externo en Jira o Azure Boards' })
  @ApiResponse({ status: 200, description: 'Estado actualizado del hallazgo y ticket' })
  async syncTicket(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) findingId: string,
  ) {
    return this.ticketingService.syncFindingTicket(user, findingId);
  }
}
