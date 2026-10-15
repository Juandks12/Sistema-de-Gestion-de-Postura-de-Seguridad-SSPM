import { ExecutionContext, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Test, TestingModule } from '@nestjs/testing';
import { ApiKeysService } from './api-keys.service';
import { PublicApiKeyGuard } from './public-api-key.guard';

describe('PublicApiKeyGuard', () => {
  let guard: PublicApiKeyGuard;
  let apiKeysService: { validateApiKey: jest.Mock };
  let reflector: { getAllAndOverride: jest.Mock };

  beforeEach(async () => {
    apiKeysService = {
      validateApiKey: jest.fn(),
    };
    reflector = {
      getAllAndOverride: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        PublicApiKeyGuard,
        { provide: ApiKeysService, useValue: apiKeysService },
        { provide: Reflector, useValue: reflector },
      ],
    }).compile();

    guard = module.get<PublicApiKeyGuard>(PublicApiKeyGuard);
  });

  const createMockContext = (headers: Record<string, string | undefined>): ExecutionContext => {
    const request = { headers };
    return {
      switchToHttp: () => ({
        getRequest: () => request,
      }),
      getHandler: () => ({}),
      getClass: () => ({}),
    } as unknown as ExecutionContext;
  };

  it('debe lanzar UnauthorizedException si no hay cabecera de autenticación', async () => {
    const ctx = createMockContext({});
    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it('debe validar la llave enviada mediante x-api-key', async () => {
    const rawKey = 'sspm_live_0123456789abcdef0123456789abcdef01234567';
    apiKeysService.validateApiKey.mockResolvedValue({
      id: 'key-1',
      organizationId: 'org-1',
      name: 'Test',
      scopes: ['findings:read'],
    });
    reflector.getAllAndOverride.mockReturnValue('findings:read');

    const ctx = createMockContext({ 'x-api-key': rawKey });
    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
    const req = ctx.switchToHttp().getRequest<{ organizationId?: string; apiKey?: unknown }>();
    expect(req.organizationId).toBe('org-1');
    expect(req.apiKey).toBeDefined();
  });

  it('debe validar la llave enviada mediante Authorization: Bearer', async () => {
    const rawKey = 'sspm_live_0123456789abcdef0123456789abcdef01234567';
    apiKeysService.validateApiKey.mockResolvedValue({
      id: 'key-1',
      organizationId: 'org-1',
      name: 'Test',
      scopes: ['alerts:read'],
    });
    reflector.getAllAndOverride.mockReturnValue('alerts:read');

    const ctx = createMockContext({ authorization: `Bearer ${rawKey}` });
    const result = await guard.canActivate(ctx);

    expect(result).toBe(true);
  });

  it('debe rechazar con UnauthorizedException si la llave no es válida', async () => {
    apiKeysService.validateApiKey.mockResolvedValue(null);
    const ctx = createMockContext({ 'x-api-key': 'sspm_live_fake' });
    await expect(guard.canActivate(ctx)).rejects.toThrow(UnauthorizedException);
  });

  it('debe rechazar con ForbiddenException si la llave no tiene el scope requerido', async () => {
    apiKeysService.validateApiKey.mockResolvedValue({
      id: 'key-1',
      organizationId: 'org-1',
      name: 'Test',
      scopes: ['alerts:read'],
    });
    reflector.getAllAndOverride.mockReturnValue('findings:read');

    const ctx = createMockContext({ 'x-api-key': 'sspm_live_valid' });
    await expect(guard.canActivate(ctx)).rejects.toThrow(ForbiddenException);
  });
});
