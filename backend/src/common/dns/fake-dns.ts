import { DnsClient, DnsLookupError, MxRecord } from './dns-client';

/** Zona DNS en memoria para pruebas. Un valor `'SERVFAIL'` simula un fallo del servidor. */
export interface FakeZone {
  txt?: Record<string, string[] | 'SERVFAIL'>;
  mx?: Record<string, MxRecord[] | 'SERVFAIL'>;
  addresses?: Record<string, string[]>;
}

export function fakeDns(zone: FakeZone): DnsClient & { queries: string[] } {
  const queries: string[] = [];
  const get = <T>(table: Record<string, T[] | 'SERVFAIL'> | undefined, name: string): T[] => {
    queries.push(name);
    const value = table?.[name.toLowerCase()];
    if (value === 'SERVFAIL') throw new DnsLookupError(name, 'ESERVFAIL');
    return value ?? [];
  };
  return {
    queries,
    txt: async (name) => get(zone.txt, name),
    mx: async (name) => get(zone.mx, name),
    addresses: async (name) => get(zone.addresses, name),
  };
}
