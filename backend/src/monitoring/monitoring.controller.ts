import { Body, Controller, Get, Patch } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiProperty, ApiTags } from '@nestjs/swagger';
import { MonitoringFrequency, UserRole } from '@prisma/client';
import { IsEnum } from 'class-validator';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { MonitoringService } from './monitoring.service';

class UpdateMonitoringDto {
  @ApiProperty({ enum: MonitoringFrequency, example: MonitoringFrequency.DAILY })
  @IsEnum(MonitoringFrequency)
  frequency!: MonitoringFrequency;
}

@ApiTags('monitoring')
@ApiBearerAuth()
@Controller('monitoring')
export class MonitoringController {
  constructor(private readonly monitoring: MonitoringService) {}

  @Get()
  @ApiOperation({ summary: 'Sección 10.4: frecuencia del monitoreo continuo y próxima auditoría de cada activo' })
  status(@CurrentUser() user: AuthUser) {
    return this.monitoring.status(user.organizationId);
  }

  @Patch()
  @Roles(UserRole.ADMIN)
  @ApiOperation({ summary: 'Cambiar la frecuencia del monitoreo continuo (OFF, DAILY o WEEKLY)' })
  update(@CurrentUser() user: AuthUser, @Body() dto: UpdateMonitoringDto) {
    return this.monitoring.update(user.organizationId, dto.frequency);
  }
}
