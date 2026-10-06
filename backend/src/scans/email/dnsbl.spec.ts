import { fakeDns } from '../../common/dns/fake-dns';
import { auditMailExchangersDnsbl, checkIpDnsbl, reverseIp } from './dnsbl';

describe('DNSBL (RFC 5782)', () => {
  describe('reverseIp', () => {
    it('invierte direcciones IPv4 correctamente', () => {
      expect(reverseIp('198.51.100.25')).toBe('25.100.51.198');
      expect(reverseIp('127.0.0.2')).toBe('2.0.0.127');
    });

    it('invierte direcciones IPv6 correctamente en formato nibbles', () => {
      const reversed = reverseIp('2001:db8::1');
      expect(reversed).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2');
    });

    it('retorna null para cadenas no válidas', () => {
      expect(reverseIp('no-es-ip')).toBeNull();
      expect(reverseIp('999.999.999.999')).toBeNull();
    });
  });

  describe('checkIpDnsbl', () => {
    it('detecta una IP listada en Spamhaus con motivo TXT', async () => {
      const dns = fakeDns({
        addresses: {
          '2.0.0.127.zen.spamhaus.org': ['127.0.0.2'],
        },
        txt: {
          '2.0.0.127.zen.spamhaus.org': ['Listed by SBL, see https://check.spamhaus.org/sbl/query/SBL2'],
        },
      });

      const listings = await checkIpDnsbl('127.0.0.2', 'mail.example.com', dns);
      expect(listings).toHaveLength(1);
      expect(listings[0]).toEqual({
        ip: '127.0.0.2',
        exchange: 'mail.example.com',
        provider: 'zen.spamhaus.org',
        returnCodes: ['127.0.0.2'],
        txt: 'Listed by SBL, see https://check.spamhaus.org/sbl/query/SBL2',
      });
    });

    it('descarta códigos de error 127.255.255.x de Spamhaus (no son listados)', async () => {
      const dns = fakeDns({
        addresses: {
          '1.2.0.192.zen.spamhaus.org': ['127.255.255.254'],
        },
      });

      const listings = await checkIpDnsbl('192.0.2.1', 'mail.example.com', dns);
      expect(listings).toHaveLength(0);
    });

    it('retorna vacío si la IP no está listada', async () => {
      const dns = fakeDns({});
      const listings = await checkIpDnsbl('192.0.2.1', 'mail.example.com', dns);
      expect(listings).toHaveLength(0);
    });
  });

  describe('auditMailExchangersDnsbl', () => {
    it('resuelve los MX y detecta si alguno de ellos está en lista negra', async () => {
      const dns = fakeDns({
        addresses: {
          'mail1.example.com': ['198.51.100.10'],
          'mail2.example.com': ['198.51.100.20'],
          '10.100.51.198.zen.spamhaus.org': ['127.0.0.4'],
          '20.100.51.198.bl.spamcop.net': ['127.0.0.2'],
        },
        txt: {
          '10.100.51.198.zen.spamhaus.org': ['Listed by XBL'],
          '20.100.51.198.bl.spamcop.net': ['Listed by SpamCop'],
        },
      });

      const res = await auditMailExchangersDnsbl(['mail1.example.com', 'mail2.example.com'], dns);
      expect(res.checked).toBe(true);
      expect(res.totalIpsChecked).toBe(2);
      expect(res.clean).toBe(false);
      expect(res.listings).toHaveLength(2);

      const providers = res.listings.map((l) => l.provider).sort();
      expect(providers).toEqual(['bl.spamcop.net', 'zen.spamhaus.org']);
    });

    it('reporta clean: true si ningún servidor MX está listado', async () => {
      const dns = fakeDns({
        addresses: {
          'mx.example.com': ['198.51.100.5'],
        },
      });

      const res = await auditMailExchangersDnsbl(['mx.example.com'], dns);
      expect(res.checked).toBe(true);
      expect(res.totalIpsChecked).toBe(1);
      expect(res.clean).toBe(true);
      expect(res.listings).toHaveLength(0);
    });

    it('no realiza consultas si la lista de MX está vacía', async () => {
      const dns = fakeDns({});
      const res = await auditMailExchangersDnsbl([], dns);
      expect(res.checked).toBe(false);
      expect(res.totalIpsChecked).toBe(0);
      expect(res.clean).toBe(true);
      expect(res.listings).toHaveLength(0);
    });
  });
});
