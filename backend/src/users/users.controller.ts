import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Param, ParseUUIDPipe, Patch, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AccountTokensService } from '../auth/account-tokens.service';
import { InviteUserDto } from '../auth/dto/account.dto';
import { CreateUserDto } from './dto/create-user.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { UsersService } from './users.service';

@ApiTags('users')
@ApiBearerAuth()
@Roles(UserRole.ADMIN)
@Controller('users')
export class UsersController {
  constructor(
    private readonly users: UsersService,
    private readonly invitations: AccountTokensService,
  ) {}

  @Get('invitations')
  @ApiOperation({ summary: 'Invitaciones pendientes de mi organización (solo ADMIN)' })
  listInvitations(@CurrentUser() user: AuthUser) {
    return this.invitations.listInvitations(user.organizationId).then((items) => ({
      items,
      emailEnabled: this.invitations.emailEnabled,
    }));
  }

  @Post('invitations')
  @ApiOperation({
    summary: 'Invitar a una persona por correo (solo ADMIN)',
    description: 'Envía un enlace para crear la cuenta con el rol indicado. Caduca a los 3 días.',
  })
  invite(@CurrentUser() user: AuthUser, @Body() dto: InviteUserDto) {
    return this.invitations.invite(user, dto.email, dto.role);
  }

  @Post('invitations/:id/resend')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Reenviar una invitación pendiente con un enlace nuevo (solo ADMIN)' })
  resendInvitation(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.invitations.resendInvitation(user, id);
  }

  @Delete('invitations/:id')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: 'Cancelar una invitación pendiente (solo ADMIN)' })
  cancelInvitation(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.invitations.cancelInvitation(user, id);
  }

  @Get()
  @ApiOperation({ summary: 'Listar usuarios de mi organización (solo ADMIN)' })
  findAll(@CurrentUser() user: AuthUser) {
    return this.users.findAll(user.organizationId);
  }

  @Get(':id')
  @ApiOperation({ summary: 'Ver un usuario de mi organización (solo ADMIN)' })
  findOne(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.users.findOne(user.organizationId, id);
  }

  @Post()
  @ApiOperation({ summary: 'Crear un usuario en mi organización (solo ADMIN)' })
  create(@CurrentUser() user: AuthUser, @Body() dto: CreateUserDto) {
    return this.users.create(user, dto);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Cambiar rol o estado de un usuario (solo ADMIN)' })
  update(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateUserDto,
  ) {
    return this.users.update(user, id, dto);
  }

  @Post(':id/reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Asignar una contraseña nueva a un usuario (solo ADMIN)',
    description: 'Cierra todas las sesiones abiertas de ese usuario. No se permite sobre la propia cuenta.',
  })
  resetPassword(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: ResetPasswordDto,
  ) {
    return this.users.resetPassword(user, id, dto);
  }

  @Post(':id/disable-mfa')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Desactivar la verificación en dos pasos de un usuario (solo ADMIN)',
    description: 'Para cuando pierde el dispositivo y no tiene códigos de recuperación. Queda auditado.',
  })
  disableMfa(@CurrentUser() user: AuthUser, @Param('id', ParseUUIDPipe) id: string) {
    return this.users.disableMfa(user, id);
  }
}
