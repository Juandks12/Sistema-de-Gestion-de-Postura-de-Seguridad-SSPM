import { Controller, Get, HttpCode, HttpStatus, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { RetentionService } from './retention.service';

@ApiTags('system')
@ApiBearerAuth()
@Controller('system/retention')
export class RetentionController {
  constructor(private readonly retention: RetentionService) {}

  @Get()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Consultar estado y parámetros de la política de retención de datos' })
  getStatus() {
    return this.retention.getStatus();
  }

  @Post('run')
  @Roles(UserRole.ADMIN)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Ejecutar manualmente la purga de datos históricos que superan el periodo de retención' })
  runRetention(@CurrentUser() user: AuthUser) {
    return this.retention.runRetention(user);
  }
}
