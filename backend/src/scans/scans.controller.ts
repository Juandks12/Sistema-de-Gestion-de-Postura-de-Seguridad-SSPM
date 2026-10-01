import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseBoolPipe,
  ParseUUIDPipe,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiQuery, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { CreateScanDto } from './dto/create-scan.dto';
import { ListScansQuery } from './dto/list-scans.query';
import { ScansService } from './scans.service';

@ApiTags('scans')
@ApiBearerAuth()
@Controller()
export class ScansController {
  constructor(private readonly scans: ScansService) {}

  @Post('assets/:assetId/scans')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Encolar un escaneo sobre un activo (ver los tipos en CreateScanDto)',
    description:
      'El escaneo se ejecuta de forma asíncrona. Consulta GET /scans/{id} para ver su estado, resultado y hallazgos.',
  })
  @ApiResponse({ status: 202, description: 'Escaneo encolado (estado PENDING).' })
  @ApiResponse({ status: 400, description: 'Activo inactivo, sin autorización o tipo no disponible.' })
  @ApiResponse({ status: 404, description: 'El activo no existe en la organización.' })
  @ApiResponse({ status: 409, description: 'Ya hay un escaneo en curso para el activo.' })
  @ApiResponse({ status: 429, description: 'Límite de escaneos por hora alcanzado.' })
  request(
    @CurrentUser() user: AuthUser,
    @Param('assetId', ParseUUIDPipe) assetId: string,
    @Body() dto: CreateScanDto,
  ) {
    return this.scans.request(user, assetId, dto);
  }

  @Post('assets/:assetId/scans/all')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Auditoría completa: encolar todos los tipos de escaneo disponibles para el activo',
    description: 'Los tipos que ya tengan un escaneo en curso se omiten y se listan en `skipped`.',
  })
  requestAll(@CurrentUser() user: AuthUser, @Param('assetId', ParseUUIDPipe) assetId: string) {
    return this.scans.requestAll(user, assetId);
  }

  @Get('assets/:assetId/exposure')
  @ApiOperation({ summary: 'Puertos abiertos del activo según su último escaneo completado' })
  exposure(@CurrentUser() user: AuthUser, @Param('assetId', ParseUUIDPipe) assetId: string) {
    return this.scans.exposure(user.organizationId, assetId);
  }

  @Get('scans')
  @ApiOperation({ summary: 'Listar escaneos de mi organización (paginado)' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListScansQuery) {
    return this.scans.findAll(user.organizationId, query);
  }

  @Get('scans/:id')
  @ApiOperation({ summary: 'Detalle de un escaneo con los puertos y servicios detectados' })
  @ApiQuery({
    name: 'includeRaw',
    required: false,
    type: Boolean,
    description: 'Incluir la salida completa de Nmap normalizada',
  })
  findOne(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Query('includeRaw', new ParseBoolPipe({ optional: true })) includeRaw?: boolean,
  ) {
    return this.scans.findOne(user.organizationId, id, includeRaw ?? false);
  }

  @Post('scans/:id/cancel')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Cancelar un escaneo pendiente o en ejecución' })
  cancel(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.scans.cancel(user.organizationId, id);
  }
}
