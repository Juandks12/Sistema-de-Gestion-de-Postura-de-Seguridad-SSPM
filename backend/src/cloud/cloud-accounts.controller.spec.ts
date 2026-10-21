import { CloudAuthType, CloudProvider, UserRole } from '@prisma/client';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { CloudAccountsController } from './cloud-accounts.controller';

describe('CloudAccountsController', () => {
  let controller: CloudAccountsController;
  let serviceMock: {
    getOnboardingTemplates: jest.Mock;
    listCspmRules: jest.Mock;
    listAccounts: jest.Mock;
    getAccountById: jest.Mock;
    testConnection: jest.Mock;
    createAccount: jest.Mock;
    verifyExistingAccount: jest.Mock;
    updateAccount: jest.Mock;
    deleteAccount: jest.Mock;
  };
  let scanServiceMock: {
    getCloudPostureSummary: jest.Mock;
    listResources: jest.Mock;
    runAccountAudit: jest.Mock;
  };

  const mockUser: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    role: UserRole.ADMIN,
    email: 'admin@demo.local',
    fullName: 'Ana Admin',
  };

  beforeEach(() => {
    serviceMock = {
      getOnboardingTemplates: jest.fn(),
      listCspmRules: jest.fn(),
      listAccounts: jest.fn(),
      getAccountById: jest.fn(),
      testConnection: jest.fn(),
      createAccount: jest.fn(),
      verifyExistingAccount: jest.fn(),
      updateAccount: jest.fn(),
      deleteAccount: jest.fn(),
    };
    scanServiceMock = {
      getCloudPostureSummary: jest.fn(),
      listResources: jest.fn(),
      runAccountAudit: jest.fn(),
    };
    controller = new CloudAccountsController(
      serviceMock as any,
      scanServiceMock as any,
    );
  });

  it('delega getOnboardingTemplate con organizationId del usuario autenticado', () => {
    serviceMock.getOnboardingTemplates.mockReturnValueOnce({ awsExternalId: 'sspm-org-org1' });
    const res = controller.getOnboardingTemplate(mockUser);
    expect(serviceMock.getOnboardingTemplates).toHaveBeenCalledWith('org-1');
    expect(res).toEqual({ awsExternalId: 'sspm-org-org1' });
  });

  it('delega listRules filtrando por proveedor si se especifica', () => {
    serviceMock.listCspmRules.mockReturnValueOnce([]);
    controller.listRules(CloudProvider.AWS);
    expect(serviceMock.listCspmRules).toHaveBeenCalledWith(CloudProvider.AWS);
  });

  it('delega getCloudSummary al servicio de escaneo CSPM', async () => {
    scanServiceMock.getCloudPostureSummary.mockResolvedValueOnce({ accounts: { total: 2 } });
    const res = await controller.getCloudSummary(mockUser);
    expect(scanServiceMock.getCloudPostureSummary).toHaveBeenCalledWith('org-1');
    expect(res).toEqual({ accounts: { total: 2 } });
  });

  it('delega listResources con los filtros indicados', async () => {
    scanServiceMock.listResources.mockResolvedValueOnce([]);
    const res = await controller.listResources(mockUser, { provider: CloudProvider.AWS });
    expect(scanServiceMock.listResources).toHaveBeenCalledWith('org-1', {
      provider: CloudProvider.AWS,
    });
    expect(res).toEqual([]);
  });

  it('delega createAccount pasando organizationId y userId', async () => {
    serviceMock.createAccount.mockResolvedValueOnce({ account: { id: 'ca-1' } });
    const dto = {
      provider: CloudProvider.AWS,
      name: 'AWS Prod',
      authType: CloudAuthType.ROLE_ARN,
      accountOrSubscriptionId: '123456789012',
      awsRoleArn: 'arn:aws:iam::123456789012:role/SSPM',
    };

    const res = await controller.createAccount(mockUser, dto);
    expect(serviceMock.createAccount).toHaveBeenCalledWith('org-1', 'user-1', dto);
    expect(res).toEqual({ account: { id: 'ca-1' } });
  });

  it('delega verifyAccount para una cuenta existente', async () => {
    serviceMock.verifyExistingAccount.mockResolvedValueOnce({ verification: { valid: true } });
    const res = await controller.verifyAccount(mockUser, 'ca-uuid-1');
    expect(serviceMock.verifyExistingAccount).toHaveBeenCalledWith('org-1', 'ca-uuid-1');
    expect(res).toEqual({ verification: { valid: true } });
  });

  it('delega scanAccount ejecutando runAccountAudit con simulate y actorId', async () => {
    scanServiceMock.runAccountAudit.mockResolvedValueOnce({ simulated: true });
    const res = await controller.scanAccount(mockUser, 'ca-uuid-1', { simulate: true });
    expect(scanServiceMock.runAccountAudit).toHaveBeenCalledWith('org-1', 'ca-uuid-1', {
      simulate: true,
      actorId: 'user-1',
    });
    expect(res).toEqual({ simulated: true });
  });

  it('delega deleteAccount pasando organizationId e id', async () => {
    serviceMock.deleteAccount.mockResolvedValueOnce({ deleted: true });
    const res = await controller.deleteAccount(mockUser, 'ca-uuid-1');
    expect(serviceMock.deleteAccount).toHaveBeenCalledWith('org-1', 'ca-uuid-1');
    expect(res).toEqual({ deleted: true });
  });
});
