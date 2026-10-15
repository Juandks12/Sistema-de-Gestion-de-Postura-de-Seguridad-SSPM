import { BadRequestException, NotFoundException } from '@nestjs/common';
import { Test, TestingModule } from '@nestjs/testing';
import { createHash } from 'node:crypto';
import { AuditService } from '../audit/audit.service';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { PrismaService } from '../prisma/prisma.service';
import { ApiKeysService } from './api-keys.service';

describe('ApiKeysService', () => {
  let service: ApiKeysService;
  let prisma: {
    apiKey: {
      create: jest.Mock;
      findMany: jest.Mock;
      findFirst: jest.Mock;
      findUnique: jest.Mock;
      update: jest.Mock;
      delete: jest.Mock;
    };
  };
  let audit: { record: jest.Mock };

  const mockActor: AuthUser = {
    id: 'user-uuid-1',
    organizationId: 'org-uuid-1',
    email: 'admin@example.com',
    fullName: 'Admin User',
    role: 'ADMIN',
  };

  beforeEach(async () => {
    prisma = {
      apiKey: {
        create: jest.fn(),
        findMany: jest.fn(),
        findFirst: jest.fn(),
        findUnique: jest.fn(),
        update: jest.fn().mockResolvedValue({}),
        delete: jest.fn().mockResolvedValue({}),
      },
    };

    audit = {
      record: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        ApiKeysService,
        { provide: PrismaService, useValue: prisma },
        { provide: AuditService, useValue: audit },
      ],
    }).compile();

    service = module.get<ApiKeysService>(ApiKeysService);
  });

  describe('create', () => {
    it('debe generar una llave con prefijo sspm_live_, hash sha256 y registrar auditoría', async () => {
      prisma.apiKey.create.mockImplementation(({ data }) =>
        Promise.resolve({
          id: 'key-1',
          organizationId: data.organizationId,
          name: data.name,
          keyPrefix: data.keyPrefix,
          scopes: data.scopes,
          isActive: true,
          expiresAt: data.expiresAt,
          lastUsedAt: null,
          createdAt: new Date(),
          updatedAt: new Date(),
          createdBy: { id: mockActor.id, fullName: mockActor.fullName, email: mockActor.email },
        }),
      );

      const result = await service.create(mockActor, {
        name: 'Wazuh Ingest',
        scopes: ['findings:read', 'alerts:read'],
      });

      expect(result.rawKey).toMatch(/^sspm_live_[0-9a-f]{48}$/);
      expect(result.keyPrefix).toMatch(/^sspm_live_[0-9a-f]{6}\.\.\.$/);
      expect(result.name).toBe('Wazuh Ingest');
      expect(result.scopes).toEqual(['findings:read', 'alerts:read']);
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({
          action: 'api_key.create',
          organizationId: mockActor.organizationId,
          target: { type: 'api_key', id: 'key-1', label: 'Wazuh Ingest' },
        }),
      );
    });

    it('debe rechazar una fecha de expiración en el pasado', async () => {
      await expect(
        service.create(mockActor, {
          name: 'Expired Key',
          expiresAt: new Date(Date.now() - 100000).toISOString(),
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('debe rechazar un scope no permitido', async () => {
      await expect(
        service.create(mockActor, {
          name: 'Invalid Scope Key',
          scopes: ['findings:read', 'admin:superpower' as unknown as string],
        }),
      ).rejects.toThrow(BadRequestException);
    });
  });

  describe('findAll', () => {
    it('debe listar las llaves filtradas por organización', async () => {
      const mockList = [{ id: 'key-1', name: 'SIEM' }];
      prisma.apiKey.findMany.mockResolvedValue(mockList);

      const list = await service.findAll('org-uuid-1');
      expect(list).toBe(mockList);
      expect(prisma.apiKey.findMany).toHaveBeenCalledWith(
        expect.objectContaining({ where: { organizationId: 'org-uuid-1' } }),
      );
    });
  });

  describe('revoke', () => {
    it('debe desactivar la llave y registrar auditoría', async () => {
      prisma.apiKey.findFirst.mockResolvedValue({
        id: 'key-1',
        organizationId: 'org-uuid-1',
        name: 'Datadog',
        keyPrefix: 'sspm_live_123456...',
        isActive: true,
      });
      prisma.apiKey.update.mockResolvedValue({
        id: 'key-1',
        isActive: false,
        name: 'Datadog',
        keyPrefix: 'sspm_live_123456...',
      });

      const res = await service.revoke(mockActor, 'key-1');
      expect(res.isActive).toBe(false);
      expect(prisma.apiKey.update).toHaveBeenCalledWith(
        expect.objectContaining({ where: { id: 'key-1' }, data: { isActive: false } }),
      );
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'api_key.revoke', target: { type: 'api_key', id: 'key-1', label: 'Datadog' } }),
      );
    });

    it('debe lanzar NotFoundException si la llave no pertenece a la organización', async () => {
      prisma.apiKey.findFirst.mockResolvedValue(null);
      await expect(service.revoke(mockActor, 'key-unknown')).rejects.toThrow(NotFoundException);
    });
  });

  describe('remove', () => {
    it('debe eliminar la llave y registrar auditoría', async () => {
      prisma.apiKey.findFirst.mockResolvedValue({
        id: 'key-1',
        organizationId: 'org-uuid-1',
        name: 'Old Key',
        keyPrefix: 'sspm_live_123456...',
      });

      const res = await service.remove(mockActor, 'key-1');
      expect(res.success).toBe(true);
      expect(prisma.apiKey.delete).toHaveBeenCalledWith({ where: { id: 'key-1' } });
      expect(audit.record).toHaveBeenCalledWith(
        expect.objectContaining({ action: 'api_key.delete' }),
      );
    });
  });

  describe('validateApiKey', () => {
    it('debe validar un token válido y actualizar lastUsedAt', async () => {
      const rawKey = 'sspm_live_0123456789abcdef0123456789abcdef01234567';
      const keyHash = createHash('sha256').update(rawKey).digest('hex');

      prisma.apiKey.findUnique.mockResolvedValue({
        id: 'key-1',
        organizationId: 'org-uuid-1',
        name: 'Valid Key',
        keyHash,
        scopes: ['findings:read'],
        isActive: true,
        expiresAt: null,
        organization: { id: 'org-uuid-1', isActive: true },
      });

      const result = await service.validateApiKey(rawKey);
      expect(result).toEqual({
        id: 'key-1',
        organizationId: 'org-uuid-1',
        name: 'Valid Key',
        scopes: ['findings:read'],
      });
      expect(prisma.apiKey.update).toHaveBeenCalledWith({
        where: { id: 'key-1' },
        data: { lastUsedAt: expect.any(Date) },
      });
    });

    it('debe retornar null si la llave está expirada', async () => {
      const rawKey = 'sspm_live_0123456789abcdef0123456789abcdef01234567';
      prisma.apiKey.findUnique.mockResolvedValue({
        id: 'key-1',
        organizationId: 'org-uuid-1',
        isActive: true,
        expiresAt: new Date(Date.now() - 5000),
        organization: { id: 'org-uuid-1', isActive: true },
      });

      const result = await service.validateApiKey(rawKey);
      expect(result).toBeNull();
    });

    it('debe retornar null si la llave o la organización están inactivas', async () => {
      const rawKey = 'sspm_live_0123456789abcdef0123456789abcdef01234567';
      prisma.apiKey.findUnique.mockResolvedValue({
        id: 'key-1',
        organizationId: 'org-uuid-1',
        isActive: false,
        expiresAt: null,
        organization: { id: 'org-uuid-1', isActive: true },
      });

      const result = await service.validateApiKey(rawKey);
      expect(result).toBeNull();
    });

    it('debe retornar null para formatos de llave inválidos', async () => {
      expect(await service.validateApiKey('')).toBeNull();
      expect(await service.validateApiKey('invalid_token')).toBeNull();
    });
  });
});
