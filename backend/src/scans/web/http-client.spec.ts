import { request } from 'undici';
import { clearDnsCache } from '../target-resolver';
import { httpProbe } from './http-client';

jest.mock('undici', () => {
  const actual = jest.requireActual('undici');
  return {
    ...actual,
    request: jest.fn(),
  };
});

describe('httpProbe', () => {
  const mockedRequest = request as unknown as jest.Mock;

  beforeEach(() => {
    clearDnsCache();
    jest.clearAllMocks();
  });

  it('rechaza esquemas no soportados (como ftp: o file:)', async () => {
    const outcome = await httpProbe('ftp://example.com/file', {
      allowPrivate: false,
      signal: new AbortController().signal,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error).toMatch(/Esquema no soportado/);
    }
  });

  it('bloquea destinos que resuelven a IPs privadas si allowPrivate es false', async () => {
    const outcome = await httpProbe('http://192.168.1.1/admin', {
      allowPrivate: false,
      signal: new AbortController().signal,
    });
    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error).toMatch(/privada o reservada/);
    }
  });

  it('realiza una petición exitosa y extrae cabeceras, estado y cuerpo', async () => {
    async function* makeBody(content: string) {
      yield Buffer.from(content);
    }
    const createMockBody = (content: string) => {
      const iter = makeBody(content);
      return Object.assign(iter, { dump: jest.fn().mockResolvedValue(undefined) });
    };

    mockedRequest.mockResolvedValueOnce({
      statusCode: 200,
      headers: {
        'content-type': 'text/html; charset=utf-8',
        'server': 'nginx/1.20',
      },
      body: createMockBody('<html>Hello World</html>'),
    });

    const outcome = await httpProbe('http://93.184.216.34/', {
      allowPrivate: false,
      signal: new AbortController().signal,
    });

    expect(outcome.ok).toBe(true);
    if (outcome.ok) {
      expect(outcome.status).toBe(200);
      expect(outcome.headers.server).toBe('nginx/1.20');
      expect(outcome.body.toString('utf-8')).toBe('<html>Hello World</html>');
      expect(outcome.hops).toHaveLength(1);
    }
  });

  it('reintenta ante fallos transitorios de socket (ECONNRESET) con éxito', async () => {
    async function* makeBody(content: string) {
      yield Buffer.from(content);
    }
    const createMockBody = (content: string) => {
      const iter = makeBody(content);
      return Object.assign(iter, { dump: jest.fn().mockResolvedValue(undefined) });
    };

    const connResetError = Object.assign(new Error('read ECONNRESET'), { code: 'ECONNRESET' });

    mockedRequest
      .mockRejectedValueOnce(connResetError)
      .mockResolvedValueOnce({
        statusCode: 200,
        headers: { 'content-type': 'text/plain' },
        body: createMockBody('Success after retry'),
      });

    const outcome = await httpProbe('http://93.184.216.34/retry', {
      allowPrivate: false,
      signal: new AbortController().signal,
      retries: 1,
    });

    expect(outcome.ok).toBe(true);
    expect(mockedRequest).toHaveBeenCalledTimes(2);
  });

  it('retorna fallo si los reintentos transitorios se agotan', async () => {
    const timeoutErr = Object.assign(new Error('ETIMEDOUT'), { code: 'ETIMEDOUT' });

    mockedRequest
      .mockRejectedValueOnce(timeoutErr)
      .mockRejectedValueOnce(timeoutErr);

    const outcome = await httpProbe('http://93.184.216.34/timeout', {
      allowPrivate: false,
      signal: new AbortController().signal,
      retries: 1,
    });

    expect(outcome.ok).toBe(false);
    if (!outcome.ok) {
      expect(outcome.error).toBe('ETIMEDOUT');
      expect(outcome.code).toBe('ETIMEDOUT');
    }
    expect(mockedRequest).toHaveBeenCalledTimes(2);
  });

  it('respeta un dispatcher persistente y no lo destruye internamente', async () => {
    async function* makeBody(content: string) {
      yield Buffer.from(content);
    }
    const createMockBody = (content: string) => {
      const iter = makeBody(content);
      return Object.assign(iter, { dump: jest.fn().mockResolvedValue(undefined) });
    };

    mockedRequest.mockResolvedValueOnce({
      statusCode: 200,
      headers: { 'content-type': 'text/plain' },
      body: createMockBody('Pooled response'),
    });

    const mockDispatcher = {
      dispatch: jest.fn(),
      close: jest.fn().mockResolvedValue(undefined),
    } as unknown as import('undici').Dispatcher;

    const outcome = await httpProbe('http://93.184.216.34/pooled', {
      allowPrivate: false,
      signal: new AbortController().signal,
      dispatcher: mockDispatcher,
    });

    expect(outcome.ok).toBe(true);
    expect(mockedRequest).toHaveBeenCalledWith(
      expect.stringContaining('/pooled'),
      expect.objectContaining({ dispatcher: mockDispatcher }),
    );
    // El cliente no debe cerrar el dispatcher del llamador
    expect(mockDispatcher.close).not.toHaveBeenCalled();
  });
});
