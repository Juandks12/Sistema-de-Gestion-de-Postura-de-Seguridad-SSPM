import { UTF8_BOM, escapeCsvField, formatCsvRow } from './csv';

describe('CSV Utilities', () => {
  describe('escapeCsvField', () => {
    it('returns empty string for null and undefined', () => {
      expect(escapeCsvField(null)).toBe('');
      expect(escapeCsvField(undefined)).toBe('');
    });

    it('formats numbers directly', () => {
      expect(escapeCsvField(42)).toBe('42');
      expect(escapeCsvField(3.14)).toBe('3.14');
      expect(escapeCsvField(-10.5)).toBe('-10.5');
      expect(escapeCsvField(NaN)).toBe('');
      expect(escapeCsvField(Infinity)).toBe('');
    });

    it('formats booleans directly', () => {
      expect(escapeCsvField(true)).toBe('true');
      expect(escapeCsvField(false)).toBe('false');
    });

    it('formats dates in ISO string format', () => {
      const d = new Date('2026-10-06T12:00:00.000Z');
      expect(escapeCsvField(d)).toBe('2026-10-06T12:00:00.000Z');
    });

    it('joins arrays with comma and spaces, escaping if needed', () => {
      expect(escapeCsvField(['prod', 'web'])).toBe('"prod, web"');
    });

    it('escapes fields with commas, newlines, and quotes according to RFC 4180', () => {
      expect(escapeCsvField('hello, world')).toBe('"hello, world"');
      expect(escapeCsvField('line1\nline2')).toBe('"line1\nline2"');
      expect(escapeCsvField('line1\r\nline2')).toBe('"line1\r\nline2"');
      expect(escapeCsvField('say "hello"')).toBe('"say ""hello"""');
    });

    it('mitigates CSV formula injection for malicious formulas', () => {
      expect(escapeCsvField('=cmd|/c calc')).toBe("'=cmd|/c calc");
      expect(escapeCsvField('+1+2')).toBe("'+1+2");
      expect(escapeCsvField('@SUM(A1:A10)')).toBe("'@SUM(A1:A10)");
      expect(escapeCsvField('\tsecret')).toBe("'\tsecret");
    });

    it('preserves numeric string literals without single quote prefix', () => {
      expect(escapeCsvField('-123')).toBe('-123');
      expect(escapeCsvField('+45.67')).toBe('+45.67');
      expect(escapeCsvField('100')).toBe('100');
    });
  });

  describe('formatCsvRow', () => {
    it('formats a row terminated by CRLF', () => {
      const row = formatCsvRow(['id-1', 'HIGH', 'Missing HSTS', 7.5]);
      expect(row).toBe('id-1,HIGH,Missing HSTS,7.5\r\n');
    });

    it('handles fields with commas in the row', () => {
      const row = formatCsvRow(['1', 'Item, with comma', 'ok']);
      expect(row).toBe('1,"Item, with comma",ok\r\n');
    });
  });

  describe('UTF8_BOM', () => {
    it('is the standard byte order mark', () => {
      expect(UTF8_BOM).toBe('\uFEFF');
    });
  });
});
