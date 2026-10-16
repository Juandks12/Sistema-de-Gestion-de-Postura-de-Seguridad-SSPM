import { ConfigService } from '@nestjs/config';
import { OpenPortHint } from '../scanner.interface';
import { buildUrl, COMMON_HTTP_PORTS, COMMON_HTTPS_PORTS, hostForUrl, webTargetsFor } from './web-targets';

describe('web-targets', () => {
  let config: jest.Mocked<ConfigService>;

  beforeEach(() => {
    config = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'WEB_HTTPS_PORTS') return undefined;
        if (key === 'WEB_HTTP_PORTS') return undefined;
        return undefined;
      }),
    } as unknown as jest.Mocked<ConfigService>;
  });

  describe('hostForUrl', () => {
    it('mantiene hostnames estándar y direcciones IPv4 sin alterar', () => {
      expect(hostForUrl('example.com')).toBe('example.com');
      expect(hostForUrl('192.168.1.1')).toBe('192.168.1.1');
    });

    it('envuelve direcciones IPv6 entre corchetes', () => {
      expect(hostForUrl('2001:db8::1')).toBe('[2001:db8::1]');
      expect(hostForUrl('::1')).toBe('[::1]');
    });
  });

  describe('buildUrl', () => {
    it('omite puertos por defecto 443 (https) y 80 (http)', () => {
      expect(buildUrl('https', 'example.com', 443)).toBe('https://example.com/');
      expect(buildUrl('http', 'example.com', 80)).toBe('http://example.com/');
      expect(buildUrl('https', 'example.com', 443, '/api')).toBe('https://example.com/api');
    });

    it('incluye puertos no estándar en la URL', () => {
      expect(buildUrl('https', 'example.com', 8443)).toBe('https://example.com:8443/');
      expect(buildUrl('http', 'example.com', 8080)).toBe('http://example.com:8080/');
      expect(buildUrl('http', '127.0.0.1', 3000, '/health')).toBe('http://127.0.0.1:3000/health');
    });
  });

  describe('webTargetsFor', () => {
    it('retorna puertos por defecto (443 https y 80 http) si no hay puertos abiertos conocidos', () => {
      const targets = webTargetsFor('example.com', [], config);
      expect(targets).toEqual([
        { scheme: 'https', port: 443, url: 'https://example.com/' },
        { scheme: 'http', port: 80, url: 'http://example.com/' },
      ]);
    });

    it('clasifica puertos HTTP y HTTPS comunes descubiertos en openPorts', () => {
      const openPorts: OpenPortHint[] = [
        { port: 8443, protocol: 'tcp', serviceName: null, tunnel: null },
        { port: 9443, protocol: 'tcp', serviceName: null, tunnel: null },
        { port: 8080, protocol: 'tcp', serviceName: null, tunnel: null },
        { port: 3000, protocol: 'tcp', serviceName: null, tunnel: null },
        { port: 53, protocol: 'udp', serviceName: null, tunnel: null }, // Debe ignorar UDP
      ];

      const targets = webTargetsFor('app.internal', openPorts, config);

      const httpsPorts = targets.filter((t) => t.scheme === 'https').map((t) => t.port);
      const httpPorts = targets.filter((t) => t.scheme === 'http').map((t) => t.port);

      expect(httpsPorts).toEqual([443, 8443, 9443]);
      expect(httpPorts).toEqual([80, 3000, 8080]);
    });

    it('reconoce servicios por nombre y tunnel ssl', () => {
      const openPorts: OpenPortHint[] = [
        { port: 7000, protocol: 'tcp', serviceName: null, tunnel: 'ssl' },
        { port: 7001, protocol: 'tcp', serviceName: 'https-alt', tunnel: null },
        { port: 7002, protocol: 'tcp', serviceName: 'http-mgmt', tunnel: null },
      ];

      const targets = webTargetsFor('srv.corp', openPorts, config);

      expect(targets).toContainEqual({ scheme: 'https', port: 7000, url: 'https://srv.corp:7000/' });
      expect(targets).toContainEqual({ scheme: 'https', port: 7001, url: 'https://srv.corp:7001/' });
      expect(targets).toContainEqual({ scheme: 'http', port: 7002, url: 'http://srv.corp:7002/' });
    });

    it('no duplica un puerto en http si ya fue clasificado como https', () => {
      const openPorts: OpenPortHint[] = [
        { port: 8080, protocol: 'tcp', serviceName: null, tunnel: 'ssl' }, // 8080 normalmente http, pero con tunnel ssl es https
      ];

      const targets = webTargetsFor('srv.corp', openPorts, config);
      const targets8080 = targets.filter((t) => t.port === 8080);

      expect(targets8080).toHaveLength(1);
      expect(targets8080[0].scheme).toBe('https');
    });

    it('respeta listas de puertos configuradas en WEB_HTTPS_PORTS y WEB_HTTP_PORTS', () => {
      config.get.mockImplementation((key: string) => {
        if (key === 'WEB_HTTPS_PORTS') return '443, 8443';
        if (key === 'WEB_HTTP_PORTS') return '80, 8000';
        return undefined;
      });

      const targets = webTargetsFor('custom.domain', [], config);
      expect(targets.map((t) => `${t.scheme}:${t.port}`)).toEqual([
        'https:443',
        'https:8443',
        'http:80',
        'http:8000',
      ]);
    });
  });

  describe('Constantes de puertos comunes', () => {
    it('contiene los puertos web esperados', () => {
      expect(COMMON_HTTPS_PORTS.has(443)).toBe(true);
      expect(COMMON_HTTPS_PORTS.has(8443)).toBe(true);
      expect(COMMON_HTTPS_PORTS.has(9443)).toBe(true);
      expect(COMMON_HTTPS_PORTS.has(4443)).toBe(true);

      expect(COMMON_HTTP_PORTS.has(80)).toBe(true);
      expect(COMMON_HTTP_PORTS.has(8080)).toBe(true);
      expect(COMMON_HTTP_PORTS.has(8000)).toBe(true);
      expect(COMMON_HTTP_PORTS.has(3000)).toBe(true);
      expect(COMMON_HTTP_PORTS.has(5000)).toBe(true);
      expect(COMMON_HTTP_PORTS.has(9000)).toBe(true);
      expect(COMMON_HTTP_PORTS.has(9090)).toBe(true);
    });
  });
});
