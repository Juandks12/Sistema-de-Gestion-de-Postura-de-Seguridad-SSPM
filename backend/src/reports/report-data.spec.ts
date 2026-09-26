import { ReportType } from '@prisma/client';
import { emptyCounts } from '../risk/scoring';
import { sampleReportData } from './__fixtures__/sample-report-data';
import { renderReport } from './pdf-renderer';
import { executiveSummary, formatEvidence, groupRecommendations, pdfSafe, prioritizedFindings } from './report-data';

describe('resumen ejecutivo', () => {
  it('explica la postura, los hallazgos urgentes y la tendencia en lenguaje de negocio', () => {
    const text = executiveSummary(sampleReportData()).join(' ');
    expect(text).toContain('se califica como deficiente (44/100, grado D)');
    expect(text).toContain('6 hallazgos abiertos');
    expect(text).toContain('3 requieren atención prioritaria');
    expect(text).toContain('mejoró 6 puntos (de 38 a 44)');
    expect(text).toContain('Se monitorean 3 activos');
  });

  it('indica que no hay datos cuando nada se ha evaluado', () => {
    const data = sampleReportData();
    data.score = { ...data.score, score: null, grade: null, counts: emptyCounts(), weekAgoScore: null };
    expect(executiveSummary(data)).toEqual([expect.stringContaining('Todavía no hay información suficiente')]);
  });
});

describe('priorización', () => {
  it('ordena los hallazgos del más grave al menos grave', () => {
    const severities = prioritizedFindings(sampleReportData()).map((f) => f.severity);
    expect(severities[0]).toBe('CRITICAL');
    expect(severities[severities.length - 1]).toBe('LOW');
  });

  it('agrupa las recomendaciones por regla y acumula los activos afectados', () => {
    const groups = groupRecommendations(sampleReportData());
    expect(groups[0]).toMatchObject({ ruleId: 'PATH-SECRETS-EXPOSED', severity: 'CRITICAL', occurrences: 1 });
    const csp = groups.find((g) => g.ruleId === 'HDR-CSP-MISSING');
    expect(csp).toMatchObject({ occurrences: 2, assets: ['tienda.example.com', 'www.example.com'] });
  });
});

describe('utilidades de texto del PDF', () => {
  it('conserva el español y sustituye lo que las fuentes estándar no pueden mostrar', () => {
    expect(pdfSafe('Contraseña, configuración, ¿señal? — “ok” …')).toBe('Contraseña, configuración, ¿señal? — “ok” …');
    expect(pdfSafe('Apache 🚀 中文')).toBe('Apache ? ??');
    expect(pdfSafe('a\u0000b\u0007c')).toBe('abc');
  });

  it('resume la evidencia en una línea', () => {
    expect(formatEvidence({ status: 200, header: null, list: ['a', 'b'], nested: { x: 1 } })).toBe(
      'status: 200 · list: a, b · nested: {"x":1}',
    );
    expect(formatEvidence(null)).toBe('');
    expect(formatEvidence({ big: 'x'.repeat(1000) }, 50)).toHaveLength(50);
  });
});

describe('renderReport', () => {
  it.each([ReportType.EXECUTIVE, ReportType.TECHNICAL])('genera un PDF válido (%s)', async (type) => {
    const { buffer, pages } = await renderReport(sampleReportData(type));
    expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
    expect(buffer.subarray(-6).toString()).toContain('%%EOF');
    expect(pages).toBeGreaterThanOrEqual(type === ReportType.EXECUTIVE ? 2 : 4);
  });

  it('genera el reporte aunque la organización no tenga activos ni historial', async () => {
    const data = sampleReportData(ReportType.TECHNICAL);
    data.assets = [];
    data.history = [];
    const { buffer } = await renderReport(data);
    expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
  });
});
