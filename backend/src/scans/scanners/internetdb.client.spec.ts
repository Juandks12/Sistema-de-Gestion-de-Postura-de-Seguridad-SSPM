import { ConfigService } from '@nestjs/config';
import { clearInternetDbCache, InternetDbClient } from './internetdb.client';

describe('InternetDbClient', () => {
  let client: InternetDbClient;
  let config: jest.Mocked<ConfigService>;
  const originalFetch = global.fetch;

  beforeEach(() => {
    clearInternetDbCache();
    config = {
      get: jest.fn().mockImplementation((key: string) => {
        if (key === 'SHODAN_INTERNETDB_URL') return 'https://internetdb.shodan.io';
        if (key === 'SHODAN_INTERNETDB_TIMEOUT_MS') return 3000;
        if (key === 'SHODAN_INTERNETDB_MAX_RETRIES') return 2;
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

  it('reutiliza la caché para llamadas sucesivas sobre la misma IP', async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        ip: '198.51.100.10',
        ports: [443],
        cpes: [],
        hostnames: [],
        tags: [],
        vulns: [],
      }),
    });
    global.fetch = fetchMock;

    const first = await client.get('198.51.100.10');
    expect(first?.ports).toEqual([443]);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    const second = await client.get('198.51.100.10');
    expect(second?.ports).toEqual([443]);
    expect(fetchMock).toHaveBeenCalledTimes(1); // Usó caché
  });

  it('permite omitir la caché con skipCache: true', async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({
        ip: '198.51.100.20',
        ports: [80],
        cpes: [],
        hostnames: [],
        tags: [],
        vulns: [],
      }),
    });
    global.fetch = fetchMock;

    await client.get('198.51.100.20');
    expect(fetchMock).toHaveBeenCalledTimes(1);

    await client.get('198.51.100.20', undefined, { skipCache: true });
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('reintenta con backoff ante errores 500 transitorios y tiene éxito', async () => {
    let callCount = 0;
    global.fetch = jest.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        return { ok: false, status: 503 };
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.30',
          ports: [22],
          cpes: [],
          hostnames: [],
          tags: [],
          vulns: [],
        }),
      };
    });

    const result = await client.get('198.51.100.30');
    expect(result?.ports).toEqual([22]);
    expect(callCount).toBe(2);
  });

  it('reintenta ante caídas de red transitorias (fetch throw) y tiene éxito', async () => {
    let callCount = 0;
    global.fetch = jest.fn().mockImplementation(async () => {
      callCount++;
      if (callCount === 1) {
        throw new Error('fetch failed: ECONNRESET');
      }
      return {
        ok: true,
        status: 200,
        json: async () => ({
          ip: '198.51.100.40',
          ports: [8080],
          cpes: [],
          hostnames: [],
          tags: [],
          vulns: [],
        }),
      };
    });

    const result = await client.get('198.51.100.40');
    expect(result?.ports).toEqual([8080]);
    expect(callCount).toBe(2);
  });

  it('maneja errores de servidor HTTP 500 tras agotar reintentos retornando null', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 500,
    });

    const result = await client.get('198.51.100.2');
    expect(result).toBeNull();
  });

  it('respeta la cancelación mediante AbortSignal sin reintentos innecesarios', async () => {
    const controller = new AbortController();
    controller.abort();

    await expect(client.get('198.51.100.1', controller.signal)).rejects.toThrow();
  });
});
