import { AlertType, FindingCategory, FindingSeverity, ScanType } from '@prisma/client';
import type { OpenedFinding } from '../findings/findings.service';
import { detectAlerts, diffOpenPorts, meetsThreshold, PortInfo } from './alert-rules';

const asset = { id: 'a1', value: 'tienda.example.com', name: 'Tienda' };

function opened(partial: Partial<OpenedFinding> & Pick<OpenedFinding, 'ruleId' | 'severity'>): OpenedFinding {
  return {
    id: `f-${partial.ruleId}-${partial.location ?? ''}`,
    category: FindingCategory.EXPOSED_SERVICE,
    title: partial.ruleId,
    location: 'tcp/22',
    evidence: {},
    reopened: false,
    ...partial,
  };
}

const port = (p: number, service: string | null = null): PortInfo => ({
  port: p,
  protocol: 'tcp',
  serviceName: service,
  product: null,
  version: null,
});

describe('diffOpenPorts', () => {
  it('devuelve solo los puertos que no estaban abiertos antes', () => {
    expect(diffOpenPorts([port(22), port(443)], [port(22), port(443), port(5432)]).map((p) => p.port)).toEqual([5432]);
    expect(diffOpenPorts([port(22)], [port(22)])).toEqual([]);
  });

  it('distingue el protocolo', () => {
    const udp = { ...port(53), protocol: 'udp' };
    expect(diffOpenPorts([port(53)], [udp])).toEqual([udp]);
  });
});

describe('meetsThreshold', () => {
  it('compara severidades de más a menos grave', () => {
    expect(meetsThreshold(FindingSeverity.CRITICAL, FindingSeverity.HIGH)).toBe(true);
    expect(meetsThreshold(FindingSeverity.HIGH, FindingSeverity.HIGH)).toBe(true);
    expect(meetsThreshold(FindingSeverity.MEDIUM, FindingSeverity.HIGH)).toBe(false);
    expect(meetsThreshold(FindingSeverity.INFO, FindingSeverity.INFO)).toBe(true);
  });
});

describe('detectAlerts', () => {
  it('el primer escaneo de puertos es la línea base y no alerta por puertos nuevos', () => {
    const alerts = detectAlerts({
      asset,
      scan: { id: 's1', type: ScanType.PORT_SCAN },
      opened: [opened({ ruleId: 'SVC-OPEN-PORT', severity: FindingSeverity.LOW })],
      newOpenPorts: null,
    });
    expect(alerts).toEqual([]);
  });

  it('alerta por puertos nuevos con la severidad del hallazgo asociado', () => {
    const alerts = detectAlerts({
      asset,
      scan: { id: 's2', type: ScanType.PORT_SCAN },
      opened: [opened({ ruleId: 'SVC-DATABASE-EXPOSED', severity: FindingSeverity.HIGH, location: 'tcp/5432' })],
      newOpenPorts: [port(5432, 'postgresql')],
    });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ type: AlertType.NEW_OPEN_PORT, severity: FindingSeverity.HIGH });
    expect(alerts[0].title).toContain('tcp/5432');
    expect(alerts[0].message).toContain('postgresql');
  });

  it('un puerto nuevo sin hallazgo relevante se notifica como severidad media', () => {
    const [alert] = detectAlerts({
      asset,
      scan: { id: 's2', type: ScanType.PORT_SCAN },
      opened: [],
      newOpenPorts: [port(8080), port(8443)],
    });
    expect(alert).toMatchObject({ type: AlertType.NEW_OPEN_PORT, severity: FindingSeverity.MEDIUM });
    expect(alert.title).toContain('2 puertos nuevos');
  });

  it('alerta por certificados caducados o por caducar', () => {
    const alerts = detectAlerts({
      asset,
      scan: { id: 's3', type: ScanType.SSL_CERT },
      opened: [
        opened({
          ruleId: 'TLS-EXPIRING-7D',
          severity: FindingSeverity.HIGH,
          category: FindingCategory.TLS_CERTIFICATE,
          location: 'tls://tienda.example.com:443',
          evidence: { validTo: '2026-10-01T00:00:00.000Z', daysUntilExpiry: 5 },
        }),
      ],
      newOpenPorts: null,
    });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ type: AlertType.CERT_EXPIRING, severity: FindingSeverity.HIGH });
    expect(alerts[0].title).toContain('5 día(s)');
    expect(alerts[0].message).toContain('2026-10-01');
  });

  it('agrupa los hallazgos críticos nuevos en una sola alerta', () => {
    const alerts = detectAlerts({
      asset,
      scan: { id: 's4', type: ScanType.SENSITIVE_PATHS },
      opened: [
        opened({ ruleId: 'PATH-SECRETS-EXPOSED', severity: FindingSeverity.CRITICAL, location: 'https://t/.env', title: '.env expuesto' }),
        opened({ ruleId: 'PATH-BACKUP-EXPOSED', severity: FindingSeverity.CRITICAL, location: 'https://t/db.sql', title: 'Backup expuesto' }),
        opened({ ruleId: 'PATH-VCS-EXPOSED', severity: FindingSeverity.HIGH, location: 'https://t/.git/HEAD' }),
      ],
      newOpenPorts: null,
    });
    expect(alerts).toHaveLength(1);
    expect(alerts[0]).toMatchObject({ type: AlertType.CRITICAL_FINDING, severity: FindingSeverity.CRITICAL });
    expect(alerts[0].title).toContain('2 hallazgos críticos');
    expect((alerts[0].data.findings as unknown[]).length).toBe(2);
  });

  it('no duplica como hallazgo crítico lo que ya cubre otra alerta', () => {
    const alerts = detectAlerts({
      asset,
      scan: { id: 's5', type: ScanType.SSL_CERT },
      opened: [
        opened({
          ruleId: 'TLS-EXPIRED',
          severity: FindingSeverity.CRITICAL,
          category: FindingCategory.TLS_CERTIFICATE,
          location: 'tls://tienda.example.com:443',
        }),
      ],
      newOpenPorts: null,
    });
    expect(alerts.map((a) => a.type)).toEqual([AlertType.CERT_EXPIRING]);
    expect(alerts[0].title).toContain('caducado');
  });

  it('no alerta por hallazgos no críticos que no son de certificados', () => {
    const alerts = detectAlerts({
      asset,
      scan: { id: 's6', type: ScanType.WEB_HEADERS },
      opened: [opened({ ruleId: 'HDR-CSP-MISSING', severity: FindingSeverity.MEDIUM, category: FindingCategory.HTTP_HEADERS })],
      newOpenPorts: null,
    });
    expect(alerts).toEqual([]);
  });
});

describe('detectAlerts - subdominios nuevos', () => {
  const scan = { id: 's5', type: ScanType.SUBDOMAIN_DISCOVERY };

  it('alerta de los subdominios nuevos fuera del inventario', () => {
    const hosts = Array.from({ length: 12 }, (_, i) => `h${String(i).padStart(2, '0')}.example.com`);
    const [alert] = detectAlerts({ asset, scan, opened: [], newOpenPorts: null, newHosts: hosts });
    expect(alert).toMatchObject({ type: AlertType.NEW_SUBDOMAIN, severity: FindingSeverity.MEDIUM, data: { hosts } });
    expect(alert.title).toBe('12 subdominios nuevos de tienda.example.com');
    expect(alert.message).toContain('h09.example.com y 2 más');

    const [single] = detectAlerts({ asset, scan, opened: [], newOpenPorts: null, newHosts: ['vpn.example.com'] });
    expect(single.title).toBe('Nuevo subdominio de tienda.example.com: vpn.example.com');
  });

  it('no alerta en la línea base ni sin novedades', () => {
    expect(detectAlerts({ asset, scan, opened: [], newOpenPorts: null, newHosts: null })).toEqual([]);
    expect(detectAlerts({ asset, scan, opened: [], newOpenPorts: null, newHosts: [] })).toEqual([]);
  });
});
