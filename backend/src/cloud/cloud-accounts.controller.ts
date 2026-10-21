import {
  Body,
  Controller,
  Delete,
  Get,
  Param,
  ParseUUIDPipe,
  Patch,
  Post,
  Query,
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiQuery,
  ApiTags,
} from '@nestjs/swagger';
import { CloudProvider, UserRole } from '@prisma/client';
import { CurrentUser } from '../common/decorators/current-user.decorator';
import { Roles } from '../common/decorators/roles.decorator';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { CloudAccountsService } from './cloud-accounts.service';
import { CloudScanService } from './cloud-scan.service';
import {
  CreateCloudAccountDto,
  ListCloudResourcesQueryDto,
  RunCloudAuditDto,
  TestCloudConnectionDto,
  UpdateCloudAccountDto,
} from './dto/cloud-account.dto';

@ApiTags('cloud')
@ApiBearerAuth()
@Controller('cloud')
export class CloudAccountsController {
  constructor(
    private readonly cloudAccounts: CloudAccountsService,
    private readonly cloudScan: CloudScanService,
  ) {}

  @Get('onboarding-template')
  @ApiOperation({
    summary: 'Obtener External ID y plantillas CloudFormation / CLI para conectar AWS y Azure',
  })
  getOnboardingTemplate(@CurrentUser() user: AuthUser) {
    return this.cloudAccounts.getOnboardingTemplates(user.organizationId);
  }

  @Get('rules')
  @ApiOperation({
    summary: 'Listar el catálogo de 31 reglas CSPM con comandos CLI y código Terraform de remediación',
  })
  @ApiQuery({ name: 'provider', enum: CloudProvider, required: false })
  listRules(@Query('provider') provider?: CloudProvider) {
    return this.cloudAccounts.listCspmRules(provider);
  }

  @Get('summary')
  @ApiOperation({
    summary: 'Obtener resumen consolidado de postura CSPM (cuentas, inventario de recursos y hallazgos cloud)',
  })
  getCloudSummary(@CurrentUser() user: AuthUser) {
    return this.cloudScan.getCloudPostureSummary(user.organizationId);
  }

  @Get('resources')
  @ApiOperation({
    summary: 'Listar el inventario de recursos cloud descubiertos en AWS y Azure con estado de hallazgos',
  })
  listResources(
    @CurrentUser() user: AuthUser,
    @Query() query: ListCloudResourcesQueryDto,
  ) {
    return this.cloudScan.listResources(user.organizationId, query);
  }

  @Get('accounts')
  @ApiOperation({
    summary: 'Listar cuentas de AWS y suscripciones de Azure conectadas en la organización',
  })
  listAccounts(@CurrentUser() user: AuthUser) {
    return this.cloudAccounts.listAccounts(user.organizationId);
  }

  @Get('accounts/:id')
  @ApiOperation({ summary: 'Obtener detalle de una cuenta cloud conectada' })
  getAccount(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.cloudAccounts.getAccountById(user.organizationId, id);
  }

  @Post('accounts/test-connection')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'Probar credenciales y conectividad real con AWS STS o Azure ARM sin guardar',
  })
  testConnection(
    @CurrentUser() user: AuthUser,
    @Body() dto: TestCloudConnectionDto,
  ) {
    return this.cloudAccounts.testConnection(user.organizationId, dto);
  }

  @Post('accounts')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'Conectar una cuenta de AWS o suscripción de Azure (cifrado AES-256-GCM y verificación)',
  })
  createAccount(
    @CurrentUser() user: AuthUser,
    @Body() dto: CreateCloudAccountDto,
  ) {
    return this.cloudAccounts.createAccount(user.organizationId, user.id, dto);
  }

  @Post('accounts/:id/verify')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'Re-verificar conectividad de una cuenta cloud existente contra AWS STS / Azure ARM',
  })
  verifyAccount(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.cloudAccounts.verifyExistingAccount(user.organizationId, id);
  }

  @Post('accounts/:id/scan')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'Ejecutar auditoría completa de postura CSPM (descubrimiento de recursos, evaluación de reglas y deduplicación de hallazgos)',
  })
  scanAccount(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto?: RunCloudAuditDto,
  ) {
    return this.cloudScan.runAccountAudit(user.organizationId, id, {
      simulate: dto?.simulate,
      actorId: user.id,
    });
  }

  @Patch('accounts/:id')
  @Roles(UserRole.ADMIN, UserRole.ANALYST)
  @ApiOperation({
    summary: 'Actualizar configuración, regiones monitoreadas o rotar credenciales de una cuenta cloud',
  })
  updateAccount(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
    @Body() dto: UpdateCloudAccountDto,
  ) {
    return this.cloudAccounts.updateAccount(user.organizationId, id, dto);
  }

  @Delete('accounts/:id')
  @Roles(UserRole.ADMIN)
  @ApiOperation({
    summary: 'Desconectar y eliminar una cuenta cloud registrada',
  })
  deleteAccount(
    @CurrentUser() user: AuthUser,
    @Param('id', ParseUUIDPipe) id: string,
  ) {
    return this.cloudAccounts.deleteAccount(user.organizationId, id);
  }
}
