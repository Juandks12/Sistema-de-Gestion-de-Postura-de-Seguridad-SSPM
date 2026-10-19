import { NotFoundException } from '@nestjs/common';
import { FindingSeverity } from '@prisma/client';
import { ComplianceFramework } from './compliance.catalog';
import { ComplianceService } from './compliance.service';

describe('ComplianceService', () => {
  let service: ComplianceService;
  let prismaMock: { finding: { findMany: jest.Mock } };

  beforeEach(() => {
    prismaMock = {
      finding: {
        findMany: jest.fn(),
      },
    };
    service = new ComplianceService(prismaMock as any);
  });

  describe('getOverview', () => {
    it('returns 100% compliance across all frameworks when there are no active findings', async () => {
      prismaMock.finding.findMany.mockResolvedValueOnce([]);

      const result = await service.getOverview('org-1');

      expect(result.globalCompliancePercentage).toBe(100);
      expect(result.totalFrameworks).toBe(5);
      expect(result.topFailingControls).toEqual([]);
      for (const fw of result.frameworks) {
        expect(fw.compliancePercentage).toBe(100);
        expect(fw.failedControls).toBe(0);
        expect(fw.failingFindingsCount).toBe(0);
        expect(fw.worstSeverity).toBeNull();
      }
    });

    it('evaluates active findings and correctly calculates failing controls and percentages', async () => {
      // Mock findings for rules HDR-HSTS-MISSING and TLS-EXPIRED
      prismaMock.finding.findMany.mockResolvedValueOnce([
        {
          id: 'f-1',
          ruleId: 'HDR-HSTS-MISSING',
          title: 'Falta cabecera HSTS',
          severity: FindingSeverity.MEDIUM,
          cvssScore: 5.3,
          location: 'https://example.com',
          assetId: 'asset-1',
          asset: { id: 'asset-1', value: 'example.com', name: 'Example Web' },
        },
        {
          id: 'f-2',
          ruleId: 'TLS-EXPIRED',
          title: 'Certificado SSL/TLS expirado',
          severity: FindingSeverity.HIGH,
          cvssScore: 7.5,
          location: 'https://example.com:443',
          assetId: 'asset-1',
          asset: { id: 'asset-1', value: 'example.com', name: 'Example Web' },
        },
      ]);

      const result = await service.getOverview('org-1');

      expect(result.totalFrameworks).toBe(5);
      expect(result.globalCompliancePercentage).toBeLessThan(100);
      expect(result.topFailingControls.length).toBeGreaterThan(0);

      // Verify that ISO_27001 summary captured failed controls
      const iso = result.frameworks.find((f) => f.metadata.id === ComplianceFramework.ISO_27001);
      expect(iso).toBeDefined();
      expect(iso!.failedControls).toBeGreaterThan(0);
      expect(iso!.failingFindingsCount).toBeGreaterThan(0);
      expect(iso!.worstSeverity).toBe(FindingSeverity.HIGH);
    });
  });

  describe('getFrameworkDetails', () => {
    it('throws NotFoundException for unrecognized framework', async () => {
      await expect(
        service.getFrameworkDetails('org-1', 'INVALID_FW' as ComplianceFramework),
      ).rejects.toThrow(NotFoundException);
    });

    it('evaluates control-by-control matrix for ISO_27001', async () => {
      prismaMock.finding.findMany.mockResolvedValueOnce([
        {
          id: 'f-1',
          ruleId: 'SVC-REMOTE-DESKTOP',
          title: 'Escritorio remoto expuesto',
          severity: FindingSeverity.CRITICAL,
          cvssScore: 9.8,
          location: '203.0.113.1:3389',
          assetId: 'asset-9',
          asset: { id: 'asset-9', value: '203.0.113.1', name: 'Gateway' },
        },
      ]);

      const result = await service.getFrameworkDetails('org-1', ComplianceFramework.ISO_27001);

      expect(result.metadata.id).toBe(ComplianceFramework.ISO_27001);
      expect(result.summary.totalControls).toBeGreaterThan(0);
      expect(result.summary.failedControls).toBeGreaterThan(0);
      expect(result.summary.worstSeverity).toBe(FindingSeverity.CRITICAL);

      const rdpControl = result.controls.find((c) => c.control.ruleIds.includes('SVC-REMOTE-DESKTOP'));
      expect(rdpControl).toBeDefined();
      expect(rdpControl!.status).toBe('NON_COMPLIANT');
      expect(rdpControl!.affectedAssetsCount).toBe(1);
      expect(rdpControl!.failingFindings).toHaveLength(1);
      expect(rdpControl!.failingFindings[0].id).toBe('f-1');
    });
  });

  describe('exportCsv', () => {
    it('generates valid CSV representation of the framework audit matrix', async () => {
      prismaMock.finding.findMany.mockResolvedValueOnce([]);

      const csv = await service.exportCsv('org-1', ComplianceFramework.PCI_DSS);

      expect(typeof csv).toBe('string');
      const lines = csv.split('\n');
      expect(lines.length).toBeGreaterThan(1);
      expect(lines[0]).toContain('Marco Regulatorio,Código de Control,Título del Control');
      expect(lines[1]).toContain('PCI-DSS v4.0');
      expect(lines[1]).toContain('CUMPLIDO');
    });
  });
});
