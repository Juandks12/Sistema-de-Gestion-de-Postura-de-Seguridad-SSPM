import { Body, Controller, Get, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { UserRole } from '../generated/prisma/client';
import { CreateMemberDto } from './dto/create-member.dto';
import { OrganizationsService } from './organizations.service';

/**
 * Todos los endpoints operan sobre la organización del usuario autenticado
 * (`/organizations/me`). Nunca se acepta un `organizationId` del cliente,
 * lo que evita accesos cruzados entre tenants.
 */
@ApiTags('organizations')
@ApiBearerAuth()
@Controller('organizations')
export class OrganizationsController {
  constructor(private readonly organizations: OrganizationsService) {}

  @Get('me')
  @ApiOperation({ summary: 'Organización del usuario autenticado' })
  getMine(@CurrentUser('organizationId') organizationId: string) {
    return this.organizations.getById(organizationId);
  }

  @Get('me/members')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Listar usuarios de la organización (solo ADMIN)' })
  listMembers(@CurrentUser('organizationId') organizationId: string) {
    return this.organizations.listMembers(organizationId);
  }

  @Post('me/members')
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Crear un usuario en la organización con un rol (solo ADMIN)' })
  createMember(
    @CurrentUser('organizationId') organizationId: string,
    @Body() dto: CreateMemberDto,
  ) {
    return this.organizations.createMember(organizationId, dto);
  }
}
