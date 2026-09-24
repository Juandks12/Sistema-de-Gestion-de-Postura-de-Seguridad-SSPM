import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  HttpStatus,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AssetsService } from './assets.service';
import { CreateAssetDto } from './dto/create-asset.dto';
import { ListAssetsQuery } from './dto/list-assets.query';
import { UpdateAssetDto } from './dto/update-asset.dto';

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
  @ApiResponse({ status: 201, description: 'Activo registrado.' })
  @ApiResponse({ status: 400, description: 'Valor inválido, privado o sin autorización confirmada.' })
  @ApiResponse({ status: 403, description: 'El rol VIEWER no puede registrar activos.' })
  @ApiResponse({ status: 409, description: 'El activo ya existe en la organización.' })
  create(@CurrentUser() user: AuthUser, @Body() dto: CreateAssetDto) {
    return this.assets.create(user, dto);
  }

  @Get()
  @ApiOperation({ summary: 'Listar activos de mi organización (paginado)' })
  findAll(@CurrentUser() user: AuthUser, @Query() query: ListAssetsQuery) {
    return this.assets.findAll(user.organizationId, query);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Detalle de un activo de mi organización' })
  @ApiResponse({ status: 404, description: 'No existe o pertenece a otra organización.' })
  findOne(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.assets.findOne(user.organizationId, id);
  }

  @Patch(':id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Actualizar nombre, descripción o estado de un activo' })
  update(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateAssetDto,
  ) {
    return this.assets.update(user.organizationId, id, dto);
  }

  @Delete(':id')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Eliminar un activo y sus escaneos (solo ADMIN)' })
  remove(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.assets.remove(user.organizationId, id);
  }
}
