import { Body, Controller, Get, Param, ParseUUIDPipe, Patch, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { DiscoveryService } from './discovery.service';
import { ImportDiscoveredHostsDto, UpdateDiscoveredHostDto } from './dto/discovery.dto';

@ApiTags('discovery')
@ApiBearerAuth()
@Controller()
export class DiscoveryController {
  constructor(private readonly discovery: DiscoveryService) {}

  @Get('assets/:assetId/discovered-hosts')
  @ApiOperation({ summary: 'Subdominios descubiertos en Certificate Transparency para un dominio del inventario' })
  @ApiResponse({ status: 404, description: 'El activo no existe en la organización.' })
  list(@CurrentUser() user: AuthUser, @Param('assetId', ParseUUIDPipe) assetId: string) {
    return this.discovery.listForAsset(user.organizationId, assetId);
  }

  @Patch('discovered-hosts/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Descartar o restaurar un subdominio descubierto' })
  update(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string, @Body() dto: UpdateDiscoveredHostDto) {
    return this.discovery.setIgnored(user.organizationId, id, dto.ignored);
  }

  @Post('discovered-hosts/import')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({ summary: 'Registrar subdominios descubiertos como activos del inventario' })
  @ApiResponse({ status: 201, description: 'Resultado por subdominio (creados y fallidos).' })
  import(@CurrentUser() user: AuthUser, @Body() dto: ImportDiscoveredHostsDto) {
    return this.discovery.importAsAssets(user, dto.ids);
  }
}
