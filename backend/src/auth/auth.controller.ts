import { Body, Controller, Delete, Get, HttpCode, HttpStatus, Patch, Post, Query, UseGuards } from '@nestjs/common';
import { SkipThrottle, ThrottlerGuard } from '@nestjs/throttler';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Public } from '../common/decorators/public.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AccountTokensService } from './account-tokens.service';
import { AuthService } from './auth.service';
import { AcceptInvitationDto, DisableMfaDto, ForgotPasswordDto, MfaCodeDto, MfaLoginDto, ResetPasswordWithTokenDto } from './dto/account.dto';
import { MfaService } from './mfa.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly auth: AuthService,
    private readonly accountTokens: AccountTokensService,
    private readonly mfa: MfaService,
  ) {}

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ login: true, forgot: true })
  @Post('register')
  @ApiOperation({ summary: 'Registrar una nueva organización y su usuario administrador' })
  @ApiResponse({ status: 201, description: 'Organización creada. Devuelve el token de acceso.' })
  @ApiResponse({ status: 409, description: 'El correo ya está registrado.' })
  @ApiResponse({ status: 429, description: 'Demasiados registros desde la misma IP.' })
  register(@Body() dto: RegisterDto) {
    return this.auth.register(dto);
  }

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ register: true, forgot: true })
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Iniciar sesión y obtener un JWT' })
  @ApiResponse({ status: 200, description: 'Token de acceso emitido.' })
  @ApiResponse({ status: 401, description: 'Credenciales inválidas.' })
  @ApiResponse({ status: 429, description: 'Cuenta bloqueada temporalmente por intentos fallidos o demasiadas peticiones desde la misma IP.' })
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto);
  }

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ register: true, forgot: true })
  @Post('login/mfa')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Segundo paso del login: código de la aplicación de autenticación o de recuperación',
    description: 'Canjea el token intermedio devuelto por /auth/login junto con el código TOTP.',
  })
  @ApiResponse({ status: 200, description: 'Token de acceso emitido.' })
  @ApiResponse({ status: 401, description: 'Código incorrecto o sesión de verificación caducada.' })
  loginMfa(@Body() dto: MfaLoginDto) {
    return this.mfa.completeLogin(dto.mfaToken, dto.code);
  }

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ login: true, register: true })
  @Post('forgot-password')
  @HttpCode(HttpStatus.ACCEPTED)
  @ApiOperation({
    summary: 'Solicitar el restablecimiento de la contraseña por correo',
    description: 'La respuesta es la misma exista o no la cuenta: no revela qué correos están registrados.',
  })
  @ApiResponse({ status: 202, description: 'Si la cuenta existe, se envía el enlace por correo.' })
  @ApiResponse({ status: 429, description: 'Demasiadas solicitudes desde la misma IP.' })
  forgotPassword(@Body() dto: ForgotPasswordDto) {
    return this.accountTokens.requestPasswordReset(dto.email);
  }

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ register: true, forgot: true })
  @Post('reset-password')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Fijar una contraseña nueva con el token del correo' })
  @ApiResponse({ status: 200, description: 'Contraseña cambiada; devuelve el token de acceso.' })
  @ApiResponse({ status: 400, description: 'Token inválido, caducado o ya usado.' })
  resetPassword(@Body() dto: ResetPasswordWithTokenDto) {
    return this.accountTokens.resetPassword(dto.token, dto.newPassword);
  }

  @Public()
  @Get('invitations/info')
  @ApiOperation({ summary: 'Datos de una invitación vigente (pantalla de aceptación)' })
  @ApiResponse({ status: 404, description: 'Invitación inválida, caducada o ya usada.' })
  invitationInfo(@Query('token') token: string) {
    return this.accountTokens.invitationInfo(token ?? '');
  }

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ register: true, forgot: true })
  @Post('invitations/accept')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: 'Aceptar una invitación: crea la cuenta e inicia sesión' })
  @ApiResponse({ status: 201, description: 'Cuenta creada; devuelve el token de acceso.' })
  @ApiResponse({ status: 400, description: 'Invitación inválida o caducada.' })
  acceptInvitation(@Body() dto: AcceptInvitationDto) {
    return this.accountTokens.acceptInvitation(dto.token, dto.fullName, dto.password);
  }

  @Get('me/mfa')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Estado de mi verificación en dos pasos' })
  mfaStatus(@CurrentUser() user: AuthUser) {
    return this.mfa.status(user);
  }

  @Post('me/mfa/setup')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Iniciar la activación de la verificación en dos pasos',
    description: 'Devuelve el secreto y la URL otpauth:// para el código QR. Se confirma con el primer código.',
  })
  mfaSetup(@CurrentUser() user: AuthUser) {
    return this.mfa.setup(user);
  }

  @Post('me/mfa/enable')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Confirmar el primer código y activar la verificación en dos pasos',
    description: 'Devuelve los códigos de recuperación una única vez.',
  })
  mfaEnable(@CurrentUser() user: AuthUser, @Body() dto: MfaCodeDto) {
    return this.mfa.enable(user, dto.code);
  }

  @Delete('me/mfa')
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Desactivar mi verificación en dos pasos (exige contraseña y código vigente)' })
  mfaDisable(@CurrentUser() user: AuthUser, @Body() dto: DisableMfaDto) {
    return this.mfa.disable(user, dto.password, dto.code);
  }

  @Get('me')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Datos del usuario autenticado' })
  me(@CurrentUser() user: AuthUser): AuthUser {
    return user;
  }

  @Patch('me/password')
  @ApiBearerAuth()
  @ApiOperation({
    summary: 'Cambiar mi contraseña',
    description: 'Cierra todas las sesiones abiertas del usuario y devuelve un token nuevo para la sesión actual.',
  })
  @ApiResponse({ status: 200, description: 'Contraseña cambiada. Devuelve el nuevo token de acceso.' })
  @ApiResponse({ status: 400, description: 'Contraseña actual incorrecta, igual a la nueva o sin cumplir la política.' })
  changePassword(@CurrentUser() user: AuthUser, @Body() dto: ChangePasswordDto) {
    return this.auth.changePassword(user, dto);
  }
}
