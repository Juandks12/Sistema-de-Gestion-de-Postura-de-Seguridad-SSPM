import { ConfigService } from '@nestjs/config';
import { InternetDbClient } from './internetdb.client';

describe('InternetDbClient', () => {
  let client: InternetDbClient;
  let config: jest.Mocked<ConfigService>;
  const originalFetch = global.fetch;

  beforeEach(() => {
    config = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'SHODAN_INTERNETDB_URL') return 'https://internetdb.shodan.io';
        if (key === 'SHODAN_INTERNETDB_TIMEOUT_MS') return 3000;
        return undefined;
      }),
    } as unknown as jest.Mocked<ConfigService>;
    client = new InternetDbClient(config);
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('obtiene y normaliza la información de puertos, cpes y vulns de InternetDB', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        ip: '198.51.100.1',
        ports: [80, 443, 8080],
        cpes: ['cpe:/a:nginx:nginx:1.20.1'],
        hostnames: ['mail.empresa.com'],
        tags: ['cloud', 'vpn'],
        vulns: ['CVE-2021-23017'],
      }),
    });

    const result = await client.get('198.51.100.1');

    expect(result).toEqual({
      ip: '198.51.100.1',
      ports: [80, 443, 8080],
      cpes: ['cpe:/a:nginx:nginx:1.20.1'],
      hostnames: ['mail.empresa.com'],
      tags: ['cloud', 'vpn'],
      vulns: ['CVE-2021-23017'],
    });
    expect(global.fetch).toHaveBeenCalledWith(
      'https://internetdb.shodan.io/198.51.100.1',
      expect.objectContaining({
        headers: expect.objectContaining({
          accept: 'application/json',
        }),
      }),
    );
  });

  it('retorna null cuando la IP no está registrada en Shodan (HTTP 404)', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 404,
    });

    const result = await client.get('203.0.113.5');
    expect(result).toBeNull();
  });

  it('retorna null sin llamar a la API si la entrada no es una IP válida', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock;

    const result = await client.get('dominio-no-ip.com');
    expect(result).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('maneja errores de servidor HTTP 500 de manera resiliente', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });

    const result = await client.get('198.51.100.2');
    expect(result).toBeNull();
  });

  it('respeta la cancelación mediante AbortSignal', async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(client.get('198.51.100.1', controller.signal)).rejects.toThrow();
  });
});
