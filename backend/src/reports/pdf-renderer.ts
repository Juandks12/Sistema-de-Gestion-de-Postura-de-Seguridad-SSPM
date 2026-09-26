import { FindingSeverity, ReportType, ScanType } from '@prisma/client';
import PDFDocument from 'pdfkit';
import { GRADE_BANDS, SCORING_MODEL_VERSION, SEVERITY_CAPS, SEVERITY_ORDER, SEVERITY_WEIGHTS } from '../risk/scoring';
import {
  assetLabel,
  executiveSummary,
  formatEvidence,
  groupRecommendations,
  pdfSafe,
  prioritizedFindings,
  ReportAsset,
  ReportData,
  SCAN_TYPE_LABEL,
  SEVERITY_LABEL,
} from './report-data';

type Doc = PDFKit.PDFDocument;

const COLOR = {
  ink: '#111827',
  ink2: '#374151',
  muted: '#6b7280',
  line: '#e5e7eb',
  surface: '#f3f4f6',
  accent: '#1e40af',
  white: '#ffffff',
};

const SEVERITY_COLOR: Record<FindingSeverity, string> = {
  CRITICAL: '#b91c1c',
  HIGH: '#c2410c',
  MEDIUM: '#a16207',
  LOW: '#1d4ed8',
  INFO: '#6b7280',
};

const GRADE_COLOR: Record<string, string> = {
  A: '#15803d',
  B: '#4d7c0f',
  C: '#a16207',
  D: '#c2410c',
  F: '#b91c1c',
};

const MARGIN = 50;
const FONT = 'Helvetica';
const FONT_BOLD = 'Helvetica-Bold';

function t(text: string): string {
  return pdfSafe(text);
}

function fmtDate(d: Date | null | undefined, withTime = false): string {
  if (!d) return '—';
  const iso = d.toISOString();
  return withTime ? `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC` : iso.slice(0, 10);
}

function contentWidth(doc: Doc): number {
  return doc.page.width - doc.page.margins.left - doc.page.margins.right;
}

function bottom(doc: Doc): number {
  return doc.page.height - doc.page.margins.bottom;
}

function ensureSpace(doc: Doc, height: number): void {
  if (doc.y + height > bottom(doc)) doc.addPage();
}

function heading(doc: Doc, text: string): void {
  ensureSpace(doc, 60);
  if (doc.y > doc.page.margins.top + 1) doc.moveDown(0.8);
  doc.font(FONT_BOLD).fontSize(14).fillColor(COLOR.ink).text(t(text), MARGIN, doc.y, { width: contentWidth(doc) });
  const y = doc.y + 3;
  doc.moveTo(MARGIN, y).lineTo(MARGIN + contentWidth(doc), y).lineWidth(0.7).strokeColor(COLOR.line).stroke();
  doc.y = y + 8;
}

function subheading(doc: Doc, text: string): void {
  ensureSpace(doc, 40);
  doc.moveDown(0.4);
  doc.font(FONT_BOLD).fontSize(11).fillColor(COLOR.ink).text(t(text), MARGIN, doc.y, { width: contentWidth(doc) });
  doc.moveDown(0.3);
}

function paragraph(doc: Doc, text: string, options: { color?: string; size?: number; bold?: boolean } = {}): void {
  const size = options.size ?? 10;
  doc.font(options.bold ? FONT_BOLD : FONT).fontSize(size);
  ensureSpace(doc, doc.heightOfString(t(text), { width: contentWidth(doc) }) + 4);
  doc.fillColor(options.color ?? COLOR.ink2).text(t(text), MARGIN, doc.y, { width: contentWidth(doc), lineGap: 2 });
  doc.moveDown(0.5);
}

interface Column {
  header: string;
  width: number;
  align?: 'left' | 'right' | 'center';
}

interface CellStyle {
  color?: string;
  bold?: boolean;
}

/** Tabla con ajuste de línea por celda y cabecera repetida en cada página. */
function table(doc: Doc, columns: Column[], rows: Array<Array<string | { text: string } & CellStyle>>): void {
  const total = columns.reduce((acc, c) => acc + c.width, 0);
  const scale = contentWidth(doc) / total;
  const widths = columns.map((c) => c.width * scale);
  const pad = 4;
  const size = 9;

  const drawHeader = () => {
    doc.font(FONT_BOLD).fontSize(size);
    const h = Math.max(...columns.map((c, i) => doc.heightOfString(t(c.header), { width: widths[i] - pad * 2 }))) + pad * 2;
    ensureSpace(doc, h + 20);
    const y = doc.y;
    doc.rect(MARGIN, y, contentWidth(doc), h).fill(COLOR.surface);
    let x = MARGIN;
    columns.forEach((c, i) => {
      doc.fillColor(COLOR.ink).text(t(c.header), x + pad, y + pad, { width: widths[i] - pad * 2, align: c.align ?? 'left' });
      x += widths[i];
    });
    doc.y = y + h;
  };

  drawHeader();
  for (const row of rows) {
    const cells = row.map((cell) => (typeof cell === 'string' ? { text: cell } : cell));
    const heights = cells.map((cell, i) => {
      doc.font(cell.bold ? FONT_BOLD : FONT).fontSize(size);
      return doc.heightOfString(t(cell.text), { width: widths[i] - pad * 2 });
    });
    const h = Math.max(...heights) + pad * 2;
    if (doc.y + h > bottom(doc)) {
      doc.addPage();
      drawHeader();
    }
    const y = doc.y;
    let x = MARGIN;
    cells.forEach((cell, i) => {
      doc
        .font(cell.bold ? FONT_BOLD : FONT)
        .fontSize(size)
        .fillColor(cell.color ?? COLOR.ink2)
        .text(t(cell.text), x + pad, y + pad, { width: widths[i] - pad * 2, align: columns[i].align ?? 'left' });
      x += widths[i];
    });
    doc.moveTo(MARGIN, y + h).lineTo(MARGIN + contentWidth(doc), y + h).lineWidth(0.5).strokeColor(COLOR.line).stroke();
    doc.y = y + h;
  }
  doc.x = MARGIN;
  doc.moveDown(0.6);
}

function severityCell(s: FindingSeverity) {
  return { text: SEVERITY_LABEL[s], color: SEVERITY_COLOR[s], bold: true };
}

function titleBlock(doc: Doc, data: ReportData, title: string): void {
  doc.rect(0, 0, doc.page.width, 96).fill(COLOR.accent);
  doc.font(FONT).fontSize(9).fillColor('#c7d2fe').text(t('SSPM · Sistema de Gestión de Postura de Seguridad'), MARGIN, 26);
  doc.font(FONT_BOLD).fontSize(20).fillColor(COLOR.white).text(t(title), MARGIN, 42, { width: contentWidth(doc) });
  doc.y = 116;
  const scope = data.scope.kind === 'ASSET' ? `Activo ${assetLabel(data.scope)}` : 'Toda la organización';
  const lines = [
    ['Organización', data.organizationName],
    ['Alcance', scope],
    ['Generado', `${fmtDate(data.generatedAt, true)} por ${data.generatedBy}`],
  ];
  for (const [k, v] of lines) {
    doc.font(FONT_BOLD).fontSize(9.5).fillColor(COLOR.muted).text(t(`${k}:`), MARGIN, doc.y, { continued: true });
    doc.font(FONT).fillColor(COLOR.ink2).text(t(`  ${v}`));
  }
  doc.moveDown(0.5);
}

function scoreBlock(doc: Doc, data: ReportData): void {
  const s = data.score;
  ensureSpace(doc, 110);
  const y = doc.y + 6;
  const boxW = 130;
  const boxH = 92;
  const color = s.grade ? GRADE_COLOR[s.grade] ?? COLOR.muted : COLOR.muted;
  doc.roundedRect(MARGIN, y, boxW, boxH, 8).fill(color);
  doc
    .font(FONT_BOLD)
    .fontSize(38)
    .fillColor(COLOR.white)
    .text(s.score === null ? '—' : String(s.score), MARGIN, y + 12, { width: boxW, align: 'center' });
  doc
    .font(FONT)
    .fontSize(10)
    .text(s.score === null ? 'Sin evaluar' : t(`de 100 · Grado ${s.grade}`), MARGIN, y + 60, { width: boxW, align: 'center' });

  const x = MARGIN + boxW + 18;
  const w = contentWidth(doc) - boxW - 18;
  doc.font(FONT_BOLD).fontSize(15).fillColor(color).text(t(`Postura ${s.label.toLowerCase()}`), x, y + 4, { width: w });
  doc.font(FONT).fontSize(10).fillColor(COLOR.ink2).text(t(s.description), x, doc.y + 2, { width: w, lineGap: 2 });
  if (s.score !== null && s.weekAgoScore !== null) {
    const delta = s.score - s.weekAgoScore;
    const trend = delta === 0 ? 'Sin cambios frente a hace 7 días' : `${delta > 0 ? '+' : ''}${delta} puntos frente a hace 7 días`;
    doc.font(FONT_BOLD).fontSize(10).fillColor(delta >= 0 ? GRADE_COLOR.A : GRADE_COLOR.F).text(t(trend), x, doc.y + 4, { width: w });
  }
  doc.y = Math.max(doc.y, y + boxH) + 12;
  doc.x = MARGIN;
}

function severityBars(doc: Doc, counts: Record<FindingSeverity, number>): void {
  const max = Math.max(1, ...SEVERITY_ORDER.map((s) => counts[s]));
  const labelW = 80;
  const numW = 30;
  const barMax = contentWidth(doc) - labelW - numW - 10;
  ensureSpace(doc, SEVERITY_ORDER.length * 20 + 10);
  for (const s of SEVERITY_ORDER) {
    const y = doc.y;
    doc.font(FONT).fontSize(9.5).fillColor(COLOR.ink2).text(t(SEVERITY_LABEL[s]), MARGIN, y + 2, { width: labelW });
    doc.rect(MARGIN + labelW, y + 1, barMax, 12).fill(COLOR.surface);
    const w = counts[s] === 0 ? 0 : Math.max(3, (counts[s] / max) * barMax);
    if (w > 0) doc.rect(MARGIN + labelW, y + 1, w, 12).fill(SEVERITY_COLOR[s]);
    doc.font(FONT_BOLD).fontSize(9.5).fillColor(COLOR.ink).text(String(counts[s]), MARGIN + labelW + barMax + 8, y + 2, { width: numW });
    doc.y = y + 19;
  }
  doc.x = MARGIN;
  doc.moveDown(0.4);
}

function historyChart(doc: Doc, points: Array<{ date: Date; score: number | null }>): void {
  const valid = points.filter((p): p is { date: Date; score: number } => p.score !== null);
  if (valid.length < 2) {
    paragraph(doc, 'Aún no hay suficientes evaluaciones para mostrar la evolución (se necesitan al menos dos días con datos).', {
      color: COLOR.muted,
    });
    return;
  }
  const h = 130;
  ensureSpace(doc, h + 30);
  const axisW = 26;
  const x0 = MARGIN + axisW;
  const y0 = doc.y + 6;
  const w = contentWidth(doc) - axisW;

  doc.font(FONT).fontSize(8).fillColor(COLOR.muted);
  for (const v of [0, 25, 50, 75, 100]) {
    const y = y0 + h - (v / 100) * h;
    doc.moveTo(x0, y).lineTo(x0 + w, y).lineWidth(0.4).strokeColor(COLOR.line).stroke();
    doc.text(String(v), MARGIN, y - 4, { width: axisW - 6, align: 'right' });
  }
  const t0 = valid[0].date.getTime();
  const span = Math.max(1, valid[valid.length - 1].date.getTime() - t0);
  const xy = valid.map((p) => [x0 + ((p.date.getTime() - t0) / span) * w, y0 + h - (p.score / 100) * h] as const);
  doc.moveTo(xy[0][0], xy[0][1]);
  for (const [x, y] of xy.slice(1)) doc.lineTo(x, y);
  doc.lineWidth(1.8).strokeColor(COLOR.accent).stroke();
  for (const [x, y] of xy) doc.circle(x, y, 2.2).fill(COLOR.accent);

  doc.fillColor(COLOR.muted).fontSize(8);
  doc.text(fmtDate(valid[0].date), x0, y0 + h + 4, { width: 80 });
  doc.text(fmtDate(valid[valid.length - 1].date), x0 + w - 80, y0 + h + 4, { width: 80, align: 'right' });
  doc.y = y0 + h + 20;
  doc.x = MARGIN;
}

function methodology(doc: Doc): void {
  heading(doc, 'Anexo: metodología del Security Score');
  paragraph(
    doc,
    'El Security Score es una métrica propia de la plataforma, inspirada en los rangos de severidad de CVSS v3.1. ' +
      'No es una puntuación CVSS oficial ni una certificación de terceros. Solo cuentan los hallazgos abiertos: ' +
      'los resueltos, los de riesgo aceptado y los falsos positivos no penalizan.',
  );
  paragraph(doc, 'Score = 100 - suma por severidad de min(tope, peso x hallazgos abiertos), acotado entre 0 y 100.', {
    bold: true,
    color: COLOR.ink,
  });
  table(
    doc,
    [
      { header: 'Severidad', width: 2 },
      { header: 'Rango CVSS v3.1', width: 2 },
      { header: 'Peso por hallazgo', width: 2, align: 'right' },
      { header: 'Tope de penalización', width: 2, align: 'right' },
    ],
    SEVERITY_ORDER.map((s) => [
      severityCell(s),
      { CRITICAL: '9.0 - 10.0', HIGH: '7.0 - 8.9', MEDIUM: '4.0 - 6.9', LOW: '0.1 - 3.9', INFO: '0.0' }[s],
      String(SEVERITY_WEIGHTS[s]),
      String(SEVERITY_CAPS[s]),
    ]),
  );
  table(
    doc,
    [
      { header: 'Score', width: 1.2 },
      { header: 'Grado', width: 1 },
      { header: 'Nivel', width: 1.5 },
      { header: 'Interpretación', width: 5 },
    ],
    GRADE_BANDS.map((b, i) => [
      i === 0 ? `${b.min} - 100` : `${b.min} - ${GRADE_BANDS[i - 1].min - 1}`,
      { text: b.grade, bold: true, color: GRADE_COLOR[b.grade] },
      b.label,
      b.description,
    ]),
  );
  paragraph(
    doc,
    `El score de la organización es la media de los scores de sus activos evaluados. Versión del modelo: ${SCORING_MODEL_VERSION}.`,
    { color: COLOR.muted, size: 9 },
  );
}

function renderExecutive(doc: Doc, data: ReportData): void {
  titleBlock(doc, data, 'Reporte ejecutivo de postura de seguridad');
  heading(doc, 'Resumen');
  scoreBlock(doc, data);
  for (const p of executiveSummary(data)) paragraph(doc, p);

  heading(doc, 'Hallazgos abiertos por severidad');
  severityBars(doc, data.score.counts);

  heading(doc, 'Evolución de la postura (últimos 30 días)');
  historyChart(doc, data.history);

  const top = prioritizedFindings(data).filter((f) => f.severity !== FindingSeverity.INFO).slice(0, 5);
  heading(doc, 'Principales riesgos');
  if (top.length === 0) {
    paragraph(doc, 'No hay riesgos abiertos que destacar.', { color: COLOR.muted });
  } else {
    table(
      doc,
      [
        { header: '#', width: 0.5 },
        { header: 'Severidad', width: 1.4 },
        { header: 'Riesgo', width: 5 },
        { header: 'Activo', width: 2.6 },
      ],
      top.map((f, i) => [String(i + 1), severityCell(f.severity), f.title, f.asset]),
    );
  }

  const groups = groupRecommendations(data);
  heading(doc, 'Recomendaciones priorizadas');
  if (groups.length === 0) {
    paragraph(doc, 'No hay acciones pendientes. Mantenga el monitoreo continuo activo.', { color: COLOR.muted });
  } else {
    groups.forEach((g, i) => {
      doc.font(FONT_BOLD).fontSize(10);
      ensureSpace(doc, doc.heightOfString(t(g.recommendation), { width: contentWidth(doc) }) + 36);
      doc.fillColor(COLOR.ink).text(t(`${i + 1}. `), MARGIN, doc.y, { continued: true });
      doc.fillColor(SEVERITY_COLOR[g.severity]).text(t(`[${SEVERITY_LABEL[g.severity]}] `), { continued: true });
      doc.fillColor(COLOR.ink).text(t(g.title));
      paragraph(doc, g.recommendation);
      const where = g.assets.length > 3 ? `${g.assets.slice(0, 3).join(', ')} y ${g.assets.length - 3} más` : g.assets.join(', ');
      paragraph(doc, `Afecta a: ${where} (${g.occurrences} ${g.occurrences === 1 ? 'caso' : 'casos'}).`, {
        color: COLOR.muted,
        size: 9,
      });
    });
  }

  if (data.scope.kind === 'ORGANIZATION' && data.assets.length > 0) {
    heading(doc, 'Activos con peor postura');
    const worst = [...data.assets]
      .filter((a) => a.score !== null)
      .sort((a, b) => (a.score ?? 0) - (b.score ?? 0))
      .slice(0, 8);
    if (worst.length === 0) {
      paragraph(doc, 'Ningún activo tiene todavía una evaluación completa.', { color: COLOR.muted });
    } else {
      table(
        doc,
        [
          { header: 'Activo', width: 5 },
          { header: 'Score', width: 1, align: 'right' },
          { header: 'Grado', width: 1, align: 'center' },
          { header: 'Críticos', width: 1.2, align: 'right' },
          { header: 'Altos', width: 1, align: 'right' },
        ],
        worst.map((a) => [
          assetLabel(a),
          String(a.score),
          { text: a.grade ?? '—', bold: true, color: a.grade ? GRADE_COLOR[a.grade] : COLOR.muted },
          String(a.counts.CRITICAL),
          String(a.counts.HIGH),
        ]),
      );
    }
  }

  heading(doc, 'Alertas');
  paragraph(
    doc,
    `En los últimos 30 días se emitieron ${data.alerts.last30Days} alerta(s) temprana(s) ` +
      `(nuevos puertos, certificados por vencer o hallazgos críticos); ${data.alerts.unacknowledged} ` +
      `${data.alerts.unacknowledged === 1 ? 'sigue pendiente' : 'siguen pendientes'} de revisión.`,
  );

  doc.addPage();
  methodology(doc);
}

function assetSection(doc: Doc, a: ReportAsset): void {
  doc.addPage();
  doc.font(FONT_BOLD).fontSize(15).fillColor(COLOR.ink).text(t(assetLabel(a)), MARGIN, doc.y, { width: contentWidth(doc) });
  const status = a.score === null ? 'Sin evaluar' : `Score ${a.score}/100 · Grado ${a.grade}`;
  doc
    .font(FONT_BOLD)
    .fontSize(10)
    .fillColor(a.grade ? GRADE_COLOR[a.grade] ?? COLOR.muted : COLOR.muted)
    .text(t(status), { continued: true })
    .font(FONT)
    .fillColor(COLOR.muted)
    .text(t(`   ${a.type === 'IP' ? 'Dirección IP' : 'Dominio'} · ${a.isActive ? 'Activo' : 'Inactivo'} · Último escaneo: ${fmtDate(a.lastScannedAt, true)}`));
  doc.moveDown(0.4);

  subheading(doc, 'Último escaneo completado por tipo');
  table(
    doc,
    [
      { header: 'Tipo de escaneo', width: 3 },
      { header: 'Fecha', width: 3 },
    ],
    (Object.keys(SCAN_TYPE_LABEL) as ScanType[]).map((type) => [SCAN_TYPE_LABEL[type], fmtDate(a.lastScanByType[type] ?? null, true)]),
  );

  subheading(doc, `Puertos abiertos (${a.openPorts.length})`);
  if (a.openPorts.length === 0) {
    paragraph(doc, a.portScanAt ? 'No se detectaron puertos abiertos.' : 'Todavía no hay un escaneo de puertos completado.', {
      color: COLOR.muted,
    });
  } else {
    table(
      doc,
      [
        { header: 'Puerto', width: 1.3 },
        { header: 'Servicio', width: 2 },
        { header: 'Producto y versión', width: 5 },
      ],
      a.openPorts.map((p) => [`${p.protocol}/${p.port}`, p.serviceName ?? '—', [p.product, p.version].filter(Boolean).join(' ') || '—']),
    );
  }

  subheading(doc, `Hallazgos abiertos (${a.findings.length})`);
  if (a.findings.length === 0) {
    paragraph(doc, 'No hay hallazgos abiertos.', { color: COLOR.muted });
  }
  for (const f of a.findings) {
    doc.font(FONT).fontSize(9.5);
    const body = [f.description, f.recommendation, formatEvidence(f.evidence)].join('\n');
    ensureSpace(doc, Math.min(220, doc.heightOfString(t(body), { width: contentWidth(doc) - 12 }) + 60));
    const y = doc.y;
    doc.font(FONT_BOLD).fontSize(10).fillColor(SEVERITY_COLOR[f.severity]).text(t(`[${SEVERITY_LABEL[f.severity]}] `), MARGIN + 10, y, {
      continued: true,
      width: contentWidth(doc) - 12,
    });
    doc.fillColor(COLOR.ink).text(t(`${f.title}${f.cvssScore !== null ? ` — CVSS ${f.cvssScore.toFixed(1)}` : ''}`));
    const meta = `${f.ruleId} · ${f.location} · detectado ${fmtDate(f.firstSeenAt)}, visto por última vez ${fmtDate(f.lastSeenAt)}`;
    doc.font(FONT).fontSize(8.5).fillColor(COLOR.muted).text(t(meta), MARGIN + 10, doc.y + 1, { width: contentWidth(doc) - 12 });
    doc.font(FONT).fontSize(9.5).fillColor(COLOR.ink2).text(t(f.description), MARGIN + 10, doc.y + 3, { width: contentWidth(doc) - 12, lineGap: 1.5 });
    doc.font(FONT_BOLD).text(t('Recomendación: '), MARGIN + 10, doc.y + 3, { continued: true, width: contentWidth(doc) - 12 });
    doc.font(FONT).text(t(f.recommendation), { lineGap: 1.5 });
    const evidence = formatEvidence(f.evidence);
    if (evidence) {
      doc.font(FONT).fontSize(8.5).fillColor(COLOR.muted).text(t(`Evidencia: ${evidence}`), MARGIN + 10, doc.y + 3, {
        width: contentWidth(doc) - 12,
      });
    }
    doc.moveTo(MARGIN, y).lineTo(MARGIN, doc.y).lineWidth(2).strokeColor(SEVERITY_COLOR[f.severity]).stroke();
    doc.y += 10;
    doc.x = MARGIN;
  }

  if (a.excluded.accepted + a.excluded.falsePositive > 0) {
    paragraph(
      doc,
      `Excluidos del score: ${a.excluded.accepted} con riesgo aceptado y ${a.excluded.falsePositive} marcados como falso positivo.`,
      { color: COLOR.muted, size: 9 },
    );
  }
}

function renderTechnical(doc: Doc, data: ReportData): void {
  titleBlock(doc, data, 'Reporte técnico de hallazgos');
  heading(doc, 'Resumen');
  const s = data.score;
  table(
    doc,
    [
      { header: 'Indicador', width: 3 },
      { header: 'Valor', width: 5 },
    ],
    [
      ['Security Score', s.score === null ? 'Sin evaluar' : `${s.score}/100 (grado ${s.grade}, ${s.label.toLowerCase()})`],
      ['Activos evaluados', data.scope.kind === 'ASSET' ? (s.score === null ? 'No' : 'Sí') : `${s.scoredAssets} de ${s.totalAssets}`],
      ...SEVERITY_ORDER.map((sev) => [{ text: `Hallazgos abiertos · ${SEVERITY_LABEL[sev]}`, color: SEVERITY_COLOR[sev] }, String(s.counts[sev])]),
      ['Alertas pendientes', String(data.alerts.unacknowledged)],
    ],
  );
  paragraph(
    doc,
    'Cada activo se detalla en su propia sección: fecha del último escaneo de cada tipo, puertos expuestos y hallazgos ' +
      'abiertos con su evidencia y la recomendación de mitigación. Los activos aparecen del peor al mejor score.',
    { color: COLOR.muted, size: 9 },
  );

  const ordered = [...data.assets].sort((a, b) => {
    if (a.score === null && b.score === null) return 0;
    if (a.score === null) return 1;
    if (b.score === null) return -1;
    return a.score - b.score;
  });
  for (const a of ordered) assetSection(doc, a);
  if (ordered.length === 0) paragraph(doc, 'La organización no tiene activos activos.', { color: COLOR.muted });

  doc.addPage();
  methodology(doc);
}

export interface RenderedPdf {
  buffer: Buffer;
  pages: number;
}

/** Genera el PDF en memoria. */
export function renderReport(data: ReportData): Promise<RenderedPdf> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({
      size: 'A4',
      margins: { top: MARGIN, bottom: MARGIN + 10, left: MARGIN, right: MARGIN },
      bufferPages: true,
      info: {
        Title: t(data.type === ReportType.EXECUTIVE ? 'Reporte ejecutivo de postura de seguridad' : 'Reporte técnico de hallazgos'),
        Author: 'SSPM - SaaS Lite',
        Subject: t(data.organizationName),
      },
    });
    const chunks: Buffer[] = [];
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('error', reject);
    doc.on('end', () => resolve({ buffer: Buffer.concat(chunks), pages }));

    if (data.type === ReportType.EXECUTIVE) renderExecutive(doc, data);
    else renderTechnical(doc, data);

    const range = doc.bufferedPageRange();
    const pages = range.count;
    for (let i = range.start; i < range.start + range.count; i += 1) {
      doc.switchToPage(i);
      const saved = doc.page.margins.bottom;
      doc.page.margins.bottom = 0;
      const y = doc.page.height - 34;
      doc.font(FONT).fontSize(8).fillColor(COLOR.muted);
      doc.text(t(`${data.organizationName} · Confidencial`), MARGIN, y, { width: contentWidth(doc) / 2, lineBreak: false });
      doc.text(t(`Página ${i + 1} de ${pages}`), MARGIN + contentWidth(doc) / 2, y, {
        width: contentWidth(doc) / 2,
        align: 'right',
        lineBreak: false,
      });
      doc.page.margins.bottom = saved;
    }
    doc.end();
  });
}
