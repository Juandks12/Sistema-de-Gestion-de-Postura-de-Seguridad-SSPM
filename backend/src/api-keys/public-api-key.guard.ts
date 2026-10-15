import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { API_KEY_SCOPE_KEY } from './api-key-auth.decorator';
import { ApiKeysService } from './api-keys.service';

@Injectable()
export class PublicApiKeyGuard implements CanActivate {
  constructor(
    private readonly apiKeysService: ApiKeysService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<Request & { organizationId?: string; apiKey?: unknown }>();
    const apiKeyHeader = request.headers['x-api-key'];
    const authHeader = request.headers['authorization'];

    let token: string | undefined;

    if (typeof apiKeyHeader === 'string' && apiKeyHeader.trim()) {
      token = apiKeyHeader.trim();
    } else if (typeof authHeader === 'string' && authHeader.trim().toLowerCase().startsWith('bearer ')) {
      token = authHeader.trim().slice(7).trim();
    }

    if (!token) {
      throw new UnauthorizedException('Falta la cabecera X-API-Key o Bearer con la llave de API');
    }

    const key = await this.apiKeysService.validateApiKey(token);
    if (!key) {
      throw new UnauthorizedException('Llave de API inválida, expirada o revocada');
    }

    const requiredScope = this.reflector.getAllAndOverride<string | undefined>(API_KEY_SCOPE_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (requiredScope && !key.scopes.includes(requiredScope)) {
      throw new ForbiddenException(`La llave de API no posee el permiso requerido: ${requiredScope}`);
    }

    request.organizationId = key.organizationId;
    request.apiKey = key;

    return true;
  }
}
