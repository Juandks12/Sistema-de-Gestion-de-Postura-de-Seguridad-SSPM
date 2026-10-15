import { StreamableFile } from '@nestjs/common';
import { Readable } from 'node:stream';

/**
 * Convierte un arreglo de objetos en un flujo NDJSON (Newline Delimited JSON)
 * óptimo para ingestores SIEM/SOAR (Splunk, Elastic, Wazuh, Fluentbit).
 */
export function toNdjsonStream(items: unknown[]): StreamableFile {
  async function* generate() {
    for (const item of items) {
      yield JSON.stringify(item) + '\n';
    }
  }

  return new StreamableFile(Readable.from(generate()), {
    type: 'application/x-ndjson; charset=utf-8',
  });
}
