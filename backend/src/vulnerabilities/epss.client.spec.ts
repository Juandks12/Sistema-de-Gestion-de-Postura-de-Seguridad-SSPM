import { ConfigService } from '@nestjs/config';
import { EpssClient } from './epss.client';

describe('EpssClient', () => {
  let client: EpssClient;
  let config: jest.Mocked<ConfigService>;
  const originalFetch = global.fetch;

  beforeEach(() => {
    config = {
      get: jest.fn().mockReturnValue('https://api.first.org/data/v1/epss'),
    } as unknown as jest.Mocked<ConfigService>;
    client = new EpssClient(config);
  });

  afterEach(() => {
    global.fetch = originalFetch;
  });

  it('obtiene puntuaciones EPSS y percentiles correctamente', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        status: 'OK',
        'status-code': 200,
        data: [
          { cve: 'CVE-2023-38606', epss: '0.028990000', percentile: '0.864190000', date: '2026-09-29' },
          { cve: 'CVE-2021-44228', epss: '0.999990000', percentile: '1.000000000', date: '2026-09-29' },
        ],
      }),
    });

    const scores = await client.scores(['cve-2023-38606', 'CVE-2021-44228'], new AbortController().signal);

    expect(scores.size).toBe(2);
    expect(scores.get('CVE-2023-38606')).toEqual({
      cve: 'CVE-2023-38606',
      epss: 0.02899,
      percentile: 0.86419,
      date: '2026-09-29',
    });
    expect(scores.get('CVE-2021-44228')).toEqual({
      cve: 'CVE-2021-44228',
      epss: 0.99999,
      percentile: 1.0,
      date: '2026-09-29',
    });
  });

  it('divide en lotes de 100 CVEs cuando la lista es extensa', async () => {
    const fetchMock = jest.fn().mockResolvedValue({
      ok: true,
      json: async () => ({ status: 'OK', 'status-code': 200, data: [] }),
    });
    global.fetch = fetchMock;

    const largeCveList = Array.from({ length: 250 }, (_, i) => `CVE-2024-${1000 + i}`);
    await client.scores(largeCveList, new AbortController().signal);

    // 250 CVEs deben dividirse en 3 peticiones (100, 100, 50)
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('retorna mapa vacío sin llamar a la API si la lista de CVEs está vacía', async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock;

    const scores = await client.scores([], new AbortController().signal);

    expect(scores.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('maneja errores HTTP de forma resiliente sin lanzar excepción', async () => {
    global.fetch = jest.fn().mockResolvedValue({
      ok: false,
      status: 503,
    });

    const scores = await client.scores(['CVE-2023-1234'], new AbortController().signal);
    expect(scores.size).toBe(0);
  });

  it('respeta la señal de aborto (AbortSignal)', async () => {
    const controller = new AbortController();
    controller.abort();

    const scores = await client.scores(['CVE-2023-1234'], controller.signal);
    expect(scores.size).toBe(0);
  });
});
