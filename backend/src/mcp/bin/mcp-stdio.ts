#!/usr/bin/env node
import * as readline from 'node:readline';

const API_KEY = process.env.SSPM_API_KEY || '';
const BASE_URL = (process.env.SSPM_API_URL || 'https://secops.inmero.co/api/v1').replace(/\/$/, '');

if (!API_KEY) {
  process.stderr.write('ADVERTENCIA: SSPM_API_KEY no está configurada en las variables de entorno.\n');
}

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

rl.on('line', async (line: string) => {
  const trimmed = line.trim();
  if (!trimmed) return;

  try {
    const rpcRequest = JSON.parse(trimmed);

    const res = await fetch(`${BASE_URL}/mcp/rpc`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-API-Key': API_KEY,
      },
      body: JSON.stringify(rpcRequest),
    });

    if (res.ok) {
      const responseData = await res.json();
      process.stdout.write(JSON.stringify(responseData) + '\n');
    } else {
      const errText = await res.text();
      const errResponse = {
        jsonrpc: '2.0',
        id: rpcRequest.id ?? null,
        error: {
          code: -32000,
          message: `Error HTTP ${res.status}: ${errText}`,
        },
      };
      process.stdout.write(JSON.stringify(errResponse) + '\n');
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    const errResponse = {
      jsonrpc: '2.0',
      id: null,
      error: {
        code: -32700,
        message: `Parse error o fallo de red: ${msg}`,
      },
    };
    process.stdout.write(JSON.stringify(errResponse) + '\n');
  }
});
