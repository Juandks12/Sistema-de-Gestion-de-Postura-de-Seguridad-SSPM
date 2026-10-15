import { StreamableFile } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Test, TestingModule } from '@nestjs/testing';
import { ApiKeysService } from '../api-keys/api-keys.service';
import { PublicApiKeyGuard } from '../api-keys/public-api-key.guard';
import { PublicApiController } from './public-api.controller';
import { PublicApiService } from './public-api.service';

describe('PublicApiController', () => {
  let controller: PublicApiController;
  let service: {
    getFindings: jest.Mock;
    getAlerts: jest.Mock;
    getPosture: jest.Mock;
    getAssets: jest.Mock;
  };

  beforeEach(async () => {
    service = {
      getFindings: jest.fn(),
      getAlerts: jest.fn(),
      getPosture: jest.fn(),
      getAssets: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [PublicApiController],
      providers: [
        { provide: PublicApiService, useValue: service },
        { provide: ApiKeysService, useValue: { validateApiKey: jest.fn() } },
        { provide: Reflector, useValue: { getAllAndOverride: jest.fn() } },
        PublicApiKeyGuard,
      ],
    }).compile();

    controller = module.get<PublicApiController>(PublicApiController);
  });

  describe('getFindings', () => {
    it('debe devolver respuesta JSON cuando no se especifica ndjson', async () => {
      const mockResult = { total: 1, since: null, items: [{ id: 'f-1' }] };
      service.getFindings.mockResolvedValue(mockResult);

      const res = await controller.getFindings('org-1', { limit: 100 });
      expect(res).toBe(mockResult);
      expect(service.getFindings).toHaveBeenCalledWith('org-1', { limit: 100 });
    });

    it('debe devolver StreamableFile cuando se solicita formato ndjson', async () => {
      const mockResult = { total: 1, since: null, items: [{ id: 'f-1', title: 'Port Open' }] };
      service.getFindings.mockResolvedValue(mockResult);

      const res = await controller.getFindings('org-1', { limit: 100, format: 'ndjson' });
      expect(res).toBeInstanceOf(StreamableFile);
    });
  });

  describe('getAlerts', () => {
    it('debe devolver alertas en JSON', async () => {
      const mockResult = { total: 1, since: null, items: [{ id: 'a-1' }] };
      service.getAlerts.mockResolvedValue(mockResult);

      const res = await controller.getAlerts('org-1', { limit: 50 });
      expect(res).toBe(mockResult);
    });

    it('debe devolver StreamableFile en formato ndjson', async () => {
      const mockResult = { total: 1, since: null, items: [{ id: 'a-1' }] };
      service.getAlerts.mockResolvedValue(mockResult);

      const res = await controller.getAlerts('org-1', { limit: 50, format: 'ndjson' });
      expect(res).toBeInstanceOf(StreamableFile);
    });
  });

  describe('getPosture', () => {
    it('debe retornar métricas de postura', async () => {
      const mockPosture = { score: 90, grade: 'A' };
      service.getPosture.mockResolvedValue(mockPosture);

      const res = await controller.getPosture('org-1');
      expect(res).toBe(mockPosture);
      expect(service.getPosture).toHaveBeenCalledWith('org-1');
    });
  });

  describe('getAssets', () => {
    it('debe devolver activos en JSON', async () => {
      const mockResult = { total: 1, items: [{ id: 'ass-1' }] };
      service.getAssets.mockResolvedValue(mockResult);

      const res = await controller.getAssets('org-1', { limit: 100 });
      expect(res).toBe(mockResult);
    });

    it('debe devolver StreamableFile cuando format=ndjson', async () => {
      const mockResult = { total: 1, items: [{ id: 'ass-1' }] };
      service.getAssets.mockResolvedValue(mockResult);

      const res = await controller.getAssets('org-1', { limit: 100, format: 'ndjson' });
      expect(res).toBeInstanceOf(StreamableFile);
    });
  });
});
