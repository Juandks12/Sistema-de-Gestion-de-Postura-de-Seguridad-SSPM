import { Body, Controller, Get, Param, ParseUUIDPipe, Post, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import type { AuthenticatedUser } from '../common/interfaces/authenticated-user.interface';
import { UserRole } from '../generated/prisma/client';
import { AssetsService } from './assets.service';
import { CreateAssetDto } from './dto/create-asset.dto';
import { ListAssetsQuery } from './dto/list-assets.query';

@ApiTags('assets')
@ApiBearerAuth()
@Controller('assets')
export class AssetsController {
  constructor(private readonly assets: AssetsService) {}

  @Post()
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'RF-01: Registrar un activo (dominio o IP) en la organización del usuario',
  })
  @ApiResponse({ status: 201, description: 'Activo registrado' })
  @ApiResponse({
    status: 400,
    description: 'Valor inválido (URL, IP privada, dominio mal formado...)',
  })
  @ApiResponse({ status: 403, description: 'El rol VIEWER no puede registrar activos' })
  @ApiResponse({ status: 409, description: 'El activo ya existe en la organización' })
  create(@CurrentUser() user: AuthenticatedUser, @Body() dto: CreateAssetDto) {
    return this.assets.create(user, dto);
  }

  @Get()
  @ApiOperation({ summary: 'Listar los activos de la organización del usuario' })
  findAll(@CurrentUser('organizationId') organizationId: string, @Query() query: ListAssetsQuery) {
    return this.assets.findAll(organizationId, query);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Detalle de un activo de la organización del usuario' })
  @ApiResponse({ status: 404, description: 'No existe o pertenece a otra organización' })
  findOne(
    @CurrentUser('organizationId') organizationId: string,
    @Param('id', new ParseUUIDPipe()) id: string,
  ) {
    return this.assets.findOne(organizationId, id);
  }
}
