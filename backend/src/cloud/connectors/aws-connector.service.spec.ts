import { CloudAuthType } from '@prisma/client';
import { AwsConnectorService } from './aws-connector.service';

describe('AwsConnectorService', () => {
  let service: AwsConnectorService;
  let configMock: { get: jest.Mock };
  let fetchSpy: jest.SpyInstance;

  beforeEach(() => {
    configMock = {
      get: jest.fn((key: string) => {
        if (key === 'AWS_SCANNER_ACCESS_KEY_ID') return 'AKIASCNNERBASE123';
        if (key === 'AWS_SCANNER_SECRET_ACCESS_KEY') return 'scanner-base-secret-xyz';
        return undefined;
      }),
    };
    service = new AwsConnectorService(configMock as any);
    fetchSpy = jest.spyOn(global, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('verifica exitosamente una cuenta AWS en modo ACCESS_KEYS mediante sts:GetCallerIdentity', async () => {
    const stsXml = `
      <GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
        <GetCallerIdentityResult>
          <Arn>arn:aws:iam::123456789012:user/sspm-cloud-auditor</Arn>
          <UserId>AIDACKCEVSQ6C2EXAMPLE</UserId>
          <Account>123456789012</Account>
        </GetCallerIdentityResult>
      </GetCallerIdentityResponse>
    `;

    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => stsXml,
    } as any);

    const res = await service.verifyConnection({
      authType: CloudAuthType.ACCESS_KEYS,
      accountId: '123456789012',
      accessKeyId: 'AKIAIOSFODNN7EXAMPLE',
      secretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    });

    expect(res.valid).toBe(true);
    expect(res.accountId).toBe('123456789012');
    expect(res.arn).toBe('arn:aws:iam::123456789012:user/sspm-cloud-auditor');
    expect(res.assumedRole).toBe(false);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('detecta discrepancia cuando las credenciales pertenecen a un Account ID distinto al registrado', async () => {
    const stsXml = `
      <GetCallerIdentityResponse>
        <GetCallerIdentityResult>
          <Arn>arn:aws:iam::999999999999:user/otro-tenant</Arn>
          <UserId>AIDA999999</UserId>
          <Account>999999999999</Account>
        </GetCallerIdentityResult>
      </GetCallerIdentityResponse>
    `;

    fetchSpy.mockResolvedValueOnce({
      ok: true,
      status: 200,
      text: async () => stsXml,
    } as any);

    const res = await service.verifyConnection({
      authType: CloudAuthType.ACCESS_KEYS,
      accountId: '123456789012',
      accessKeyId: 'AKIA999',
      secretAccessKey: 'secret999',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toContain('999999999999');
    expect(res.error).toContain('123456789012');
  });

  it('ejecuta sts:AssumeRole con ExternalId y verifica identidad en modo ROLE_ARN', async () => {
    const assumeRoleXml = `
      <AssumeRoleResponse>
        <AssumeRoleResult>
          <Credentials>
            <AccessKeyId>ASIATEMPKEY12345</AccessKeyId>
            <SecretAccessKey>temp-secret-xyz</SecretAccessKey>
            <SessionToken>FwoGZXIvYXdzE...Token</SessionToken>
          </Credentials>
        </AssumeRoleResult>
      </AssumeRoleResponse>
    `;

    const callerIdentityXml = `
      <GetCallerIdentityResponse>
        <GetCallerIdentityResult>
          <Arn>arn:aws:sts::123456789012:assumed-role/SSPM-Cloud-Auditor-Role/sspm-cspm-auditor-session</Arn>
          <UserId>AROAEXAMPLE:sspm-cspm-auditor-session</UserId>
          <Account>123456789012</Account>
        </GetCallerIdentityResult>
      </GetCallerIdentityResponse>
    `;

    fetchSpy
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => assumeRoleXml,
      } as any)
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        text: async () => callerIdentityXml,
      } as any);

    const res = await service.verifyConnection({
      authType: CloudAuthType.ROLE_ARN,
      accountId: '123456789012',
      roleArn: 'arn:aws:iam::123456789012:role/SSPM-Cloud-Auditor-Role',
      externalId: 'sspm-org-a647713e537143c1',
    });

    expect(res.valid).toBe(true);
    expect(res.assumedRole).toBe(true);
    expect(res.accountId).toBe('123456789012');
    expect(fetchSpy).toHaveBeenCalledTimes(2);
    // Verificar que ExternalId se envió en el body de AssumeRole
    const firstCallArgs = fetchSpy.mock.calls[0][1];
    expect(firstCallArgs.body).toContain('ExternalId=sspm-org-a647713e537143c1');
  });

  it('retorna valid=false con el mensaje de error de AWS cuando las credenciales son inválidas', async () => {
    const errorXml = `
      <ErrorResponse>
        <Error>
          <Code>InvalidClientTokenId</Code>
          <Message>The security token included in the request is invalid.</Message>
        </Error>
      </ErrorResponse>
    `;

    fetchSpy.mockResolvedValueOnce({
      ok: false,
      status: 403,
      text: async () => errorXml,
    } as any);

    const res = await service.verifyConnection({
      authType: CloudAuthType.ACCESS_KEYS,
      accountId: '123456789012',
      accessKeyId: 'AKIAINVALID',
      secretAccessKey: 'bad-secret',
    });

    expect(res.valid).toBe(false);
    expect(res.error).toContain('The security token included in the request is invalid');
  });
});
