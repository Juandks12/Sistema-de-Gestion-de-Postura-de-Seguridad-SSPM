import { createHash, createHmac } from 'crypto';

export interface AwsCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
}

export interface SignAwsRequestParams {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD';
  url: string;
  region: string;
  service: string;
  credentials: AwsCredentials;
  headers?: Record<string, string>;
  body?: string;
  now?: Date;
}

export interface SignedAwsRequest {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: string;
}

function sha256Hex(data: string): string {
  return createHash('sha256').update(data, 'utf8').digest('hex');
}

function hmacSha256(key: Buffer | string, data: string): Buffer {
  return createHmac('sha256', key).update(data, 'utf8').digest();
}

function encodeRfc3986(str: string): string {
  return encodeURIComponent(str).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * Firma una petición HTTP hacia cualquier API de AWS utilizando el estándar criptográfico
 * oficial AWS Signature Version 4 (AWS4-HMAC-SHA256).
 */
export function signAwsRequest(params: SignAwsRequestParams): SignedAwsRequest {
  const parsedUrl = new URL(params.url);
  const now = params.now ?? new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const bodyPayload = params.body ?? '';
  const payloadHash = sha256Hex(bodyPayload);

  // Construir cabeceras base en minúsculas para canonización
  const rawHeaders: Record<string, string> = {};
  if (params.headers) {
    for (const [k, v] of Object.entries(params.headers)) {
      rawHeaders[k.toLowerCase().trim()] = v.trim();
    }
  }

  rawHeaders['host'] = parsedUrl.host;
  rawHeaders['x-amz-date'] = amzDate;
  rawHeaders['x-amz-content-sha256'] = payloadHash;

  if (params.credentials.sessionToken) {
    rawHeaders['x-amz-security-token'] = params.credentials.sessionToken;
  }

  // Ordenar cabeceras alfabéticamente
  const sortedHeaderKeys = Object.keys(rawHeaders).sort();
  const canonicalHeaders = sortedHeaderKeys
    .map((k) => `${k}:${rawHeaders[k].replace(/\s+/g, ' ')}\n`)
    .join('');
  const signedHeaders = sortedHeaderKeys.join(';');

  // Construir Canonical Query String ordenado por clave y valor RFC3986
  const queryEntries: Array<[string, string]> = [];
  parsedUrl.searchParams.forEach((val, key) => {
    queryEntries.push([encodeRfc3986(key), encodeRfc3986(val)]);
  });
  queryEntries.sort((a, b) => (a[0] === b[0] ? a[1].localeCompare(b[1]) : a[0].localeCompare(b[0])));
  const canonicalQueryString = queryEntries.map(([k, v]) => `${k}=${v}`).join('&');

  // Construir Canonical URI
  const canonicalUri = parsedUrl.pathname
    .split('/')
    .map((seg) => encodeRfc3986(decodeURIComponent(seg)))
    .join('/') || '/';

  // 1. Canonical Request
  const canonicalRequest = [
    params.method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  // 2. String to Sign
  const credentialScope = `${dateStamp}/${params.region}/${params.service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  // 3. Derivar llave de firma (Signing Key)
  const kDate = hmacSha256(`AWS4${params.credentials.secretAccessKey}`, dateStamp);
  const kRegion = hmacSha256(kDate, params.region);
  const kService = hmacSha256(kRegion, params.service);
  const kSigning = hmacSha256(kService, 'aws4_request');

  // 4. Calcular firma final
  const signature = createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

  const authorizationHeader =
    `AWS4-HMAC-SHA256 Credential=${params.credentials.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const finalHeaders: Record<string, string> = {
    ...rawHeaders,
    Authorization: authorizationHeader,
  };

  return {
    url: params.url,
    method: params.method,
    headers: finalHeaders,
    body: params.body,
  };
}
