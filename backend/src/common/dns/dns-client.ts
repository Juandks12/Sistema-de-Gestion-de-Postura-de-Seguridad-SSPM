import { Resolver } from 'node:dns/promises';

/** Registro MX. `exchange` vacío o "." es un "null MX" (RFC 7505): el dominio no recibe correo. */
export interface MxRecord {
  exchange: string;
  priority: number;
}

/**
 * Consultas DNS de los escáneres pasivos (seguridad del correo y
 * descubrimiento de subdominios). Se inyecta con `DNS_CLIENT` para poder
 * sustituirla en las pruebas.
 *
 * Un nombre inexistente o sin registros de ese tipo devuelve una lista vacía;
 * un fallo del servidor o un timeout lanza `DnsLookupError`, para no confundir
 * "no hay registro" con "no se pudo comprobar".
 */
export interface DnsClient {
  /** Registros TXT con sus fragmentos ya concatenados. */
  txt(name: string): Promise<string[]>;
  mx(name: string): Promise<MxRecord[]>;
  /** Direcciones A y AAAA. */
  addresses(name: string): Promise<string[]>;
}

export const DNS_CLIENT = Symbol('DNS_CLIENT');

export class DnsLookupError extends Error {
  constructor(
    readonly hostname: string,
    readonly code: string,
  ) {
    super(`No se pudo consultar el DNS de ${hostname} (${code})`);
    this.name = 'DnsLookupError';
  }
}

const NOT_FOUND = new Set(['ENOTFOUND', 'ENODATA', 'ENONAME', 'NXDOMAIN', 'ENOTIMP']);

async function orEmpty<T>(name: string, query: () => Promise<T[]>): Promise<T[]> {
  try {
    return await query();
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code ?? 'ERROR';
    if (NOT_FOUND.has(code)) return [];
    throw new DnsLookupError(name, code);
  }
}

/** Cliente por defecto: resolvedor del sistema con timeout corto. */
export function createDnsClient(timeoutMs = 4000): DnsClient {
  const resolver = new Resolver({ timeout: timeoutMs, tries: 2 });
  return {
    txt: async (name) => (await orEmpty(name, () => resolver.resolveTxt(name))).map((chunks) => chunks.join('')),
    mx: (name) => orEmpty(name, () => resolver.resolveMx(name)),
    addresses: async (name) => {
      const [v4, v6] = await Promise.all([
        orEmpty(name, () => resolver.resolve4(name)),
        orEmpty(name, () => resolver.resolve6(name)),
      ]);
      return [...v4, ...v6];
    },
  };
}
