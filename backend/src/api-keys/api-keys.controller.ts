import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, ParseUUIDPipe, Patch, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ApiKeysService } from './api-keys.service';
import { CreateApiKeyDto } from './dto/create-api-key.dto';

@ApiTags('api-keys')
@ApiBearerAuth()
@Roles(UserRole.ADMIN)
@Controller('api-keys')
export class ApiKeysController {
  constructor(private readonly apiKeysService: ApiKeysService) {}

  @Get()
  @ApiOperation({ summary: 'Listar las llaves de API de la organización (solo administradores)' })
  findAll(@CurrentUser() user: AuthUser) {
    return this.apiKeysService.findAll(user.organizationId);
  }

  @Post()
  @ApiOperation({ summary: 'Crear una nueva llave de API para integración SIEM/SOAR' })
  @ApiResponse({
    status: 201,
    description: 'Llave creada exitosamente. Incluye el campo rawKey con el secreto completo mostrado únicamente esta vez.',
  })
  create(@CurrentUser() user: AuthUser, @Body() dto: CreateApiKeyDto) {
    return this.apiKeysService.create(user, dto);
  }

  @Patch(':id/revoke')
  @ApiOperation({ summary: 'Revocar inmediatamente una llave de API activa' })
  revoke(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.apiKeysService.revoke(user, id);
  }

  @Delete(':id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Eliminar una llave de API de la organización' })
  async remove(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    await this.apiKeysService.remove(user, id);
  }
}
