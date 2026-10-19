import { BadRequestException } from '@nestjs/common';
import { UserRole } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ComplianceFramework } from './compliance.catalog';
import { ComplianceController } from './compliance.controller';

describe('ComplianceController', () => {
  let controller: ComplianceController;
  let serviceMock: {
    getOverview: jest.Mock;
    getFrameworkDetails: jest.Mock;
    exportCsv: jest.Mock;
  };

  const mockUser: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    role: UserRole.ADMIN,
    email: 'admin@demo.local',
    fullName: 'Admin User',
  };

  beforeEach(() => {
    serviceMock = {
      getOverview: jest.fn(),
      getFrameworkDetails: jest.fn(),
      exportCsv: jest.fn(),
    };
    controller = new ComplianceController(serviceMock as any);
  });

  describe('getOverview', () => {
    it('delegates to complianceService.getOverview with user organizationId', async () => {
      serviceMock.getOverview.mockResolvedValueOnce({ globalCompliancePercentage: 100 });

      const res = await controller.getOverview(mockUser);

      expect(serviceMock.getOverview).toHaveBeenCalledWith('org-1');
      expect(res).toEqual({ globalCompliancePercentage: 100 });
    });
  });

  describe('getFrameworkDetails', () => {
    it('calls getFrameworkDetails for valid framework', async () => {
      serviceMock.getFrameworkDetails.mockResolvedValueOnce({ metadata: {} });

      const res = await controller.getFrameworkDetails(mockUser, 'ISO_27001');

      expect(serviceMock.getFrameworkDetails).toHaveBeenCalledWith('org-1', ComplianceFramework.ISO_27001);
      expect(res).toEqual({ metadata: {} });
    });

    it('throws BadRequestException for invalid framework string', async () => {
      expect(() => controller.getFrameworkDetails(mockUser, 'INVALID_FRAMEWORK')).toThrow(
        BadRequestException,
      );
    });
  });

  describe('export', () => {
    it('generates a StreamableFile with CSV content for valid framework', async () => {
      serviceMock.exportCsv.mockResolvedValueOnce('Header1,Header2\nVal1,Val2');

      const streamableFile = await controller.export(mockUser, 'PCI_DSS');

      expect(serviceMock.exportCsv).toHaveBeenCalledWith('org-1', ComplianceFramework.PCI_DSS);
      expect(streamableFile).toBeDefined();
    });

    it('throws BadRequestException for invalid export framework', async () => {
      await expect(controller.export(mockUser, 'UNKNOWN')).rejects.toThrow(BadRequestException);
    });
  });
});
