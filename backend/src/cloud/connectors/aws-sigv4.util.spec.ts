import { signAwsRequest } from './aws-sigv4.util';

describe('signAwsRequest (AWS Signature Version 4)', () => {
  const fixedDate = new Date('2026-10-20T12:00:00.000Z');
  const credentials = {
    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
    secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  };

  it('genera una firma AWS4-HMAC-SHA256 determinística con cabeceras obligatorias', () => {
    const signed = signAwsRequest({
      method: 'POST',
      url: 'https://sts.amazonaws.com/',
      region: 'us-east-1',
      service: 'sts',
      credentials,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded; charset=utf-8',
      },
      body: 'Action=GetCallerIdentity&Version=2011-06-15',
      now: fixedDate,
    });

    expect(signed.headers['x-amz-date']).toBe('20261020T120000Z');
    expect(signed.headers['host']).toBe('sts.amazonaws.com');
    expect(signed.headers['x-amz-content-sha256']).toHaveLength(64);
    expect(signed.headers['Authorization']).toContain(
      'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261020/us-east-1/sts/aws4_request',
    );
    expect(signed.headers['Authorization']).toContain(
      'SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date',
    );
    expect(signed.headers['Authorization']).toMatch(/Signature=[0-9a-f]{64}$/);
  });

  it('incluye x-amz-security-token cuando se suministra un SessionToken temporal (STS AssumeRole)', () => {
    const signed = signAwsRequest({
      method: 'GET',
      url: 'https://s3.us-east-1.amazonaws.com/?publicAccessBlock=',
      region: 'us-east-1',
      service: 's3',
      credentials: {
        ...credentials,
        sessionToken: 'AQoDYXdzEJr...TokenTemporal',
      },
      now: fixedDate,
    });

    expect(signed.headers['x-amz-security-token']).toBe('AQoDYXdzEJr...TokenTemporal');
    expect(signed.headers['Authorization']).toContain('x-amz-security-token');
  });
});
