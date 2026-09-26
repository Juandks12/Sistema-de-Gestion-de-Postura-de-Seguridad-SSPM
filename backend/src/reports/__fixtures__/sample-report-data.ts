import { FindingCategory, FindingSeverity, ReportType } from '@prisma/client';
import { emptyCounts } from '../../risk/scoring';
import { ReportData, ReportFinding } from '../report-data';

const DAY = 24 * 60 * 60 * 1000;
const NOW = new Date('2026-09-26T12:00:00Z');

function finding(partial: Partial<ReportFinding> & Pick<ReportFinding, 'ruleId' | 'severity' | 'title'>): ReportFinding {
  return {
    id: `f-${partial.ruleId}-${partial.location ?? 'x'}`,
    category: FindingCategory.EXPOSED_SERVICE,
    cvssScore: 7.5,
    description: 'Descripción del hallazgo con acentos: configuración, autenticación, contraseña y señal.',
    recommendation: 'Restrinja el acceso por firewall y habilite autenticación fuerte.',
    location: 'tcp/5432',
    evidence: { port: 5432, service: 'postgresql', product: 'PostgreSQL DB 9.6' },
    firstSeenAt: new Date(NOW.getTime() - 10 * DAY),
    lastSeenAt: NOW,
    ...partial,
  };
}

/** Datos de ejemplo realistas para probar el renderizado de los reportes. */
export function sampleReportData(type: ReportType = ReportType.EXECUTIVE): ReportData {
  const tienda = [
    finding({ ruleId: 'PATH-SECRETS-EXPOSED', severity: FindingSeverity.CRITICAL, cvssScore: 9.8, title: 'Archivo de secretos expuesto (.env)', category: FindingCategory.SENSITIVE_PATH, location: 'https://tienda.example.com/.env', evidence: { status: 200, contentType: 'text/plain' }, recommendation: 'Elimine el archivo del directorio público y rote todas las credenciales que contenía.' }),
    finding({ ruleId: 'SVC-DATABASE-EXPOSED', severity: FindingSeverity.HIGH, title: 'Base de datos accesible desde Internet' }),
    finding({ ruleId: 'TLS-EXPIRING-7D', severity: FindingSeverity.HIGH, cvssScore: 7.4, title: 'Certificado TLS caduca en menos de 7 días', category: FindingCategory.TLS_CERTIFICATE, location: 'tls://tienda.example.com:443', evidence: { validTo: '2026-10-01T00:00:00Z', daysUntilExpiry: 5, issuer: "CN=R11, O=Let's Encrypt" }, recommendation: 'Renueve el certificado antes de la fecha de expiración.' }),
    finding({ ruleId: 'HDR-CSP-MISSING', severity: FindingSeverity.MEDIUM, cvssScore: 5.3, title: 'Falta la cabecera Content-Security-Policy', category: FindingCategory.HTTP_HEADERS, location: 'https://tienda.example.com/', evidence: { status: 200 }, recommendation: 'Defina una política CSP restrictiva.' }),
    finding({ ruleId: 'HDR-SERVER-VERSION', severity: FindingSeverity.LOW, cvssScore: 3.1, title: 'El servidor revela su versión', category: FindingCategory.HTTP_HEADERS, location: 'https://tienda.example.com/', evidence: { header: 'Apache/2.4.41 (Ubuntu) 🚀' }, recommendation: 'Oculte la versión del servidor.' }),
  ];
  const web = [
    finding({ ruleId: 'HDR-CSP-MISSING', severity: FindingSeverity.MEDIUM, cvssScore: 5.3, title: 'Falta la cabecera Content-Security-Policy', category: FindingCategory.HTTP_HEADERS, location: 'https://www.example.com/', recommendation: 'Defina una política CSP restrictiva.' }),
  ];
  const count = (list: ReportFinding[]) => {
    const c = emptyCounts();
    for (const f of list) c[f.severity] += 1;
    return c;
  };
  const total = count([...tienda, ...web]);
  return {
    type,
    generatedAt: NOW,
    generatedBy: 'Ana Admin',
    organizationName: 'Demo PyME S.A.S.',
    scope: { kind: 'ORGANIZATION' },
    score: {
      score: 44,
      grade: 'D',
      label: 'Deficiente',
      description: 'Riesgos altos abiertos. Priorizar la remediación esta semana.',
      counts: total,
      scoredAssets: 2,
      totalAssets: 3,
      weekAgoScore: 38,
    },
    history: Array.from({ length: 12 }, (_, i) => ({
      date: new Date(NOW.getTime() - (11 - i) * 2 * DAY),
      score: [30, 30, 34, 36, 38, 38, 40, 41, 41, 43, 44, 44][i],
    })),
    assets: [
      {
        id: 'a1',
        type: 'DOMAIN',
        value: 'tienda.example.com',
        name: 'Tienda en línea',
        isActive: true,
        scored: true,
        score: 21,
        grade: 'F',
        counts: count(tienda),
        lastScannedAt: NOW,
        lastScanByType: { PORT_SCAN: NOW, WEB_HEADERS: NOW, SSL_CERT: NOW, SENSITIVE_PATHS: NOW },
        openPorts: [
          { port: 22, protocol: 'tcp', serviceName: 'ssh', product: 'OpenSSH', version: '8.9p1' },
          { port: 443, protocol: 'tcp', serviceName: 'https', product: 'Apache httpd', version: '2.4.41' },
          { port: 5432, protocol: 'tcp', serviceName: 'postgresql', product: 'PostgreSQL DB', version: '9.6.0 or later' },
        ],
        portScanAt: NOW,
        findings: tienda,
        excluded: { accepted: 1, falsePositive: 0 },
      },
      {
        id: 'a2',
        type: 'DOMAIN',
        value: 'www.example.com',
        name: null,
        isActive: true,
        scored: true,
        score: 96,
        grade: 'A',
        counts: count(web),
        lastScannedAt: NOW,
        lastScanByType: { WEB_HEADERS: NOW },
        openPorts: [],
        portScanAt: null,
        findings: web,
        excluded: { accepted: 0, falsePositive: 0 },
      },
      {
        id: 'a3',
        type: 'IP',
        value: '203.0.113.10',
        name: 'VPN',
        isActive: true,
        scored: false,
        score: null,
        grade: null,
        counts: emptyCounts(),
        lastScannedAt: null,
        lastScanByType: {},
        openPorts: [],
        portScanAt: null,
        findings: [],
        excluded: { accepted: 0, falsePositive: 0 },
      },
    ],
    alerts: { last30Days: 4, unacknowledged: 2 },
  };
}
