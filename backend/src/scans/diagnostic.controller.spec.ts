import { DiagnosticProfile } from '@prisma/client';
import { UserRole } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { DiagnosticController } from './diagnostic.controller';
import { DiagnosticOrchestratorService } from './diagnostic-orchestrator.service';

describe('DiagnosticController', () => {
  let controller: DiagnosticController;
  let orchestratorMock: {
    start: jest.Mock;
    getLatestBatchForAsset: jest.Mock;
    getBatch: jest.Mock;
    getPostureDiff: jest.Mock;
    cancelBatch: jest.Mock;
  };

  const mockUser: AuthUser = {
    id: 'user-uuid-1',
    organizationId: 'org-uuid-1',
    role: UserRole.ADMIN,
    email: 'admin@demo.local',
    fullName: 'Admin User',
  };

  beforeEach(() => {
    orchestratorMock = {
      start: jest.fn(),
      getLatestBatchForAsset: jest.fn(),
      getBatch: jest.fn(),
      getPostureDiff: jest.fn(),
      cancelBatch: jest.fn(),
    };
    controller = new DiagnosticController(orchestratorMock as unknown as DiagnosticOrchestratorService);
  });

  describe('start', () => {
    it('delega el inicio del lote 360° al orquestador con el perfil indicado', async () => {
      const mockResult = { id: 'batch-1', profile: DiagnosticProfile.COMMERCE_360 };
      orchestratorMock.start.mockResolvedValueOnce(mockResult);

      const res = await controller.start(mockUser, 'asset-1', {
        profile: DiagnosticProfile.COMMERCE_360,
      });

      expect(orchestratorMock.start).toHaveBeenCalledWith(
        mockUser,
        'asset-1',
        DiagnosticProfile.COMMERCE_360,
      );
      expect(res).toEqual(mockResult);
    });

    it('utiliza perfil FULL_AUDIT por defecto si no se especifica', async () => {
      const mockResult = { id: 'batch-2', profile: DiagnosticProfile.FULL_AUDIT };
      orchestratorMock.start.mockResolvedValueOnce(mockResult);

      const res = await controller.start(mockUser, 'asset-1', {});

      expect(orchestratorMock.start).toHaveBeenCalledWith(
        mockUser,
        'asset-1',
        undefined,
      );
      expect(res).toEqual(mockResult);
    });
  });

  describe('getLatest', () => {
    it('delega la búsqueda del lote más reciente del activo', async () => {
      const mockBatch = { id: 'batch-latest', progressPercentage: 100 };
      orchestratorMock.getLatestBatchForAsset.mockResolvedValueOnce(mockBatch);

      const res = await controller.getLatest(mockUser, 'asset-1');

      expect(orchestratorMock.getLatestBatchForAsset).toHaveBeenCalledWith('org-uuid-1', 'asset-1');
      expect(res).toEqual(mockBatch);
    });
  });

  describe('getBatch', () => {
    it('delega la consulta del lote por batchId al orquestador', async () => {
      const mockBatch = { id: 'batch-specific', stages: [] };
      orchestratorMock.getBatch.mockResolvedValueOnce(mockBatch);

      const res = await controller.getBatch(mockUser, 'batch-specific');

      expect(orchestratorMock.getBatch).toHaveBeenCalledWith('org-uuid-1', 'batch-specific');
      expect(res).toEqual(mockBatch);
    });
  });

  describe('getPostureDiff', () => {
    it('delega el cálculo de comparativa de postura temporal', async () => {
      const mockDiff = { deltaScore: 12, remediatedFindings: [] };
      orchestratorMock.getPostureDiff.mockResolvedValueOnce(mockDiff);

      const res = await controller.getPostureDiff(mockUser, 'asset-1', {
        fromBatchId: 'b-old',
        toBatchId: 'b-new',
      });

      expect(orchestratorMock.getPostureDiff).toHaveBeenCalledWith(
        'org-uuid-1',
        'asset-1',
        'b-old',
        'b-new',
      );
      expect(res).toEqual(mockDiff);
    });
  });

  describe('cancel', () => {
    it('delega la cancelación del lote al orquestador', async () => {
      const mockCancelled = { id: 'batch-cancelled', status: 'CANCELLED' };
      orchestratorMock.cancelBatch.mockResolvedValueOnce(mockCancelled);

      const res = await controller.cancel(mockUser, 'batch-cancelled');

      expect(orchestratorMock.cancelBatch).toHaveBeenCalledWith('org-uuid-1', 'batch-cancelled');
      expect(res).toEqual(mockCancelled);
    });
  });
});
