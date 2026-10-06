/**
 * Utilidades para exportación segura a formato CSV (RFC 4180) con
 * protección contra inyección de fórmulas (CWE-1236 / OWASP CSV Injection)
 * y codificación UTF-8 con BOM para compatibilidad con Microsoft Excel.
 */

export const UTF8_BOM = '\uFEFF';

const DANGEROUS_FORMULA_PREFIXES = new Set(['=', '+', '-', '@', '\t', '\r']);

/**
 * Escapa un valor individual para una celda CSV según RFC 4180 y previene fórmulas maliciosas.
 */
export function escapeCsvField(val: unknown): string {
  if (val === null || val === undefined) {
    return '';
  }

  if (typeof val === 'number') {
    return Number.isFinite(val) ? String(val) : '';
  }

  if (typeof val === 'boolean') {
    return val ? 'true' : 'false';
  }

  let text: string;
  if (val instanceof Date) {
    text = val.toISOString();
  } else if (Array.isArray(val)) {
    text = val.join(', ');
  } else if (typeof val === 'object') {
    text = JSON.stringify(val);
  } else {
    text = String(val);
  }

  // Sanitización de fórmulas (OWASP CSV Injection) para texto:
  // Si empieza con =, +, -, @, \t, \r y no es un número simple, prefijar con comilla simple.
  if (text.length > 0 && DANGEROUS_FORMULA_PREFIXES.has(text[0])) {
    const isPureNumber = /^[+-]?\d+(?:\.\d+)?$/.test(text);
    if (!isPureNumber) {
      text = `'${text}`;
    }
  }

  // RFC 4180: si contiene comillas, comas, o saltos de línea, rodear con comillas dobles
  // y duplicar cualquier comilla interna.
  if (/[",\r\n]/.test(text)) {
    return `"${text.replace(/"/g, '""')}"`;
  }

  return text;
}

/**
 * Convierte un array de celdas en una línea CSV con terminador CRLF (\r\n) según RFC 4180.
 */
export function formatCsvRow(fields: unknown[]): string {
  return fields.map(escapeCsvField).join(',') + '\r\n';
}
