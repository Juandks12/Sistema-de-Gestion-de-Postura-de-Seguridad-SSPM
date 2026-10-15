import { createParamDecorator, ExecutionContext, SetMetadata } from '@nestjs/common';

export const API_KEY_SCOPE_KEY = 'apiKeyScope';

/** Exige un scope específico para invocar el endpoint mediante API Key */
export const RequireApiKeyScope = (scope: string) => SetMetadata(API_KEY_SCOPE_KEY, scope);

export interface AuthenticatedApiKey {
  id: string;
  organizationId: string;
  name: string;
  scopes: string[];
}

/** Obtiene la API Key validada de la petición pública */
export const CurrentApiKey = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): AuthenticatedApiKey => {
    const request = ctx.switchToHttp().getRequest();
    return request.apiKey;
  },
);

/** Obtiene el ID de la organización resuelto desde la API Key */
export const CurrentOrgId = createParamDecorator(
  (_data: unknown, ctx: ExecutionContext): string => {
    const request = ctx.switchToHttp().getRequest();
    return request.organizationId;
  },
);
