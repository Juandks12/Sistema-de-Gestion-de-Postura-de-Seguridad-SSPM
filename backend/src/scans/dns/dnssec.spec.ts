import { DohQueryFn, lookupDnssec, parseDnskeyRecord, parseDsRecord } from './dnssec';

describe('DNSSEC (RFC 4033, 4034, 4035)', () => {
  describe('parseDsRecord', () => {
    it('parsea un registro DS válido', () => {
      const parsed = parseDsRecord('2371 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9');
      expect(parsed).toEqual({
        keyTag: 2371,
        algorithm: 13,
        digestType: 2,
        digest: '32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9',
        raw: '2371 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9',
      });
    });

    it('retorna null para registros inválidos', () => {
      expect(parseDsRecord('invalido')).toBeNull();
      expect(parseDsRecord('abc def ghi')).toBeNull();
    });
  });

  describe('parseDnskeyRecord', () => {
    it('parsea un registro DNSKEY válido', () => {
      const parsed = parseDnskeyRecord('257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==');
      expect(parsed).toEqual({
        flags: 257,
        protocol: 3,
        algorithm: 13,
        publicKey: 'mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==',
        raw: '257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==',
      });
    });

    it('retorna null para registros DNSKEY inválidos', () => {
      expect(parseDnskeyRecord('invalid-dnskey')).toBeNull();
    });
  });

  describe('lookupDnssec', () => {
    it('reporta secure cuando los registros DS, DNSKEY y la bandera AD son válidos', async () => {
      const fakeDoh: DohQueryFn = async (_name, type) => {
        if (type === 'DS') {
          return {
            Status: 0,
            AD: true,
            Answer: [
              { name: 'example.com', type: 43, TTL: 3600, data: '2371 13 2 32996839A6D808AFE3EB4A795A0E6A7A39A76FC52FF228B22B76F6D63826F2B9' },
              { name: 'example.com', type: 46, TTL: 3600, data: 'rrsig-ds' },
            ],
          };
        }
        return {
          Status: 0,
          AD: true,
          Answer: [
            { name: 'example.com', type: 48, TTL: 3600, data: '257 3 13 pubkey123' },
            { name: 'example.com', type: 46, TTL: 3600, data: 'rrsig-dnskey' },
          ],
        };
      };

      const res = await lookupDnssec('example.com', fakeDoh);
      expect(res.status).toBe('secure');
      expect(res.adFlag).toBe(true);
      expect(res.dsRecords).toHaveLength(1);
      expect(res.dnskeyRecords).toHaveLength(1);
      expect(res.rrsigCount).toBe(2);
      expect(res.error).toBeUndefined();
    });

    it('reporta insecure cuando el dominio no tiene registros DS ni DNSKEY', async () => {
      const fakeDoh: DohQueryFn = async () => ({
        Status: 0,
        AD: false,
        Answer: [],
      });

      const res = await lookupDnssec('example.com', fakeDoh);
      expect(res.status).toBe('insecure');
      expect(res.adFlag).toBe(false);
      expect(res.dsRecords).toHaveLength(0);
      expect(res.dnskeyRecords).toHaveLength(0);
    });

    it('reporta bogus cuando el resolutor devuelve SERVFAIL (Status 2)', async () => {
      const fakeDoh: DohQueryFn = async () => ({
        Status: 2,
        AD: false,
        Answer: [],
      });

      const res = await lookupDnssec('broken-dnssec.example.com', fakeDoh);
      expect(res.status).toBe('bogus');
      expect(res.error).toContain('SERVFAIL');
    });

    it('reporta bogus si hay registro DS pero no hay DNSKEY en la zona hija', async () => {
      const fakeDoh: DohQueryFn = async (_name, type) => {
        if (type === 'DS') {
          return {
            Status: 0,
            AD: true,
            Answer: [{ name: 'example.com', type: 43, TTL: 3600, data: '2371 13 2 32996839A6D808AF' }],
          };
        }
        return {
          Status: 0,
          AD: false,
          Answer: [],
        };
      };

      const res = await lookupDnssec('example.com', fakeDoh);
      expect(res.status).toBe('bogus');
      expect(res.error).toContain('no se encontraron registros DNSKEY');
    });

    it('reporta indeterminate si ocurre un fallo de red', async () => {
      const fakeDoh: DohQueryFn = async () => {
        throw new Error('Timeout de red');
      };

      const res = await lookupDnssec('example.com', fakeDoh);
      expect(res.status).toBe('indeterminate');
      expect(res.error).toContain('Timeout de red');
    });
  });
});
