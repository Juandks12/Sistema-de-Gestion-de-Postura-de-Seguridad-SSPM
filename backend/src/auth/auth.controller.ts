import { Body, Controller, Get, HttpCode, HttpStatus, Patch, Post, UseGuards } from '@nestjs/common';
import { SkipThrottle, ThrottlerGuard } from '@nestjs/throttler';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Public } from '../common/decorators/public.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { AuthService } from './auth.service';
import { ChangePasswordDto } from './dto/change-password.dto';
import { LoginDto } from './dto/login.dto';
import { RegisterDto } from './dto/register.dto';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @UseGuards(ThrottlerGuard)
  @SkipThrottle({ login: true })
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
  @SkipThrottle({ register: true })
  @Post('login')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Iniciar sesión y obtener un JWT' })
  @ApiResponse({ status: 200, description: 'Token de acceso emitido.' })
  @ApiResponse({ status: 401, description: 'Credenciales inválidas.' })
  @ApiResponse({ status: 429, description: 'Cuenta bloqueada temporalmente por intentos fallidos o demasiadas peticiones desde la misma IP.' })
  login(@Body() dto: LoginDto) {
    return this.auth.login(dto);
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
