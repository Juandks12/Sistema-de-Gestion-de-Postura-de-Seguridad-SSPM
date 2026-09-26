import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, ParseUUIDPipe, Patch, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AlertsService } from './alerts.service';
import { CreateAlertChannelDto, ListAlertsQuery, UpdateAlertChannelDto } from './dto/alerts.dto';

/** Las rutas estáticas van antes de las de `:id` para que no las capture ParseUUIDPipe. */
@ApiTags('alerts')
@ApiBearerAuth()
@Controller('alerts')
export class AlertsController {
  constructor(private readonly alerts: AlertsService) {}

  @Get()
  @ApiOperation({ summary: 'RF-10: alertas de mi organización, las más recientes primero' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListAlertsQuery) {
    return this.alerts.findAll(user.organizationId, query);
  }

  @Get('summary')
  @ApiOperation({ summary: 'Alertas pendientes de revisar, por severidad' })
  summary(@CurrentUser() user: AuthUser) {
    return this.alerts.summary(user.organizationId);
  }

  @Post('acknowledge-all')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Marcar todas las alertas pendientes como revisadas' })
  acknowledgeAll(@CurrentUser() user: AuthUser) {
    return this.alerts.acknowledgeAll(user);
  }

  @Get('channels')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Canales de notificación (correo y webhooks). Las URL de webhook se muestran enmascaradas' })
  listChannels(@CurrentUser() user: AuthUser) {
    return this.alerts.listChannels(user.organizationId);
  }

  @Post('channels')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Crear un canal de correo o webhook (Slack, Discord o JSON genérico)' })
  createChannel(@CurrentUser() user: AuthUser, @Body() dto: CreateAlertChannelDto) {
    return this.alerts.createChannel(user, dto);
  }

  @Patch('channels/:id')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Editar nombre, destino, severidad mínima o estado de un canal' })
  updateChannel(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateAlertChannelDto) {
    return this.alerts.updateChannel(user, id, dto);
  }

  @Delete('channels/:id')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Eliminar un canal de notificación' })
  deleteChannel(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.alerts.deleteChannel(user, id);
  }

  @Post('channels/:id/test')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Enviar una notificación de prueba por el canal' })
  testChannel(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.alerts.testChannel(user, id);
  }

  @Post(':id/acknowledge')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Marcar una alerta como revisada' })
  acknowledge(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.alerts.acknowledge(user, id);
  }
}
