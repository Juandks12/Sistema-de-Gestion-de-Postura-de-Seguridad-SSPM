import { Test, TestingModule } from '@nestjs/testing';
import { AuthUser } from '../common/interfaces/auth-user.interface';
import { ApiKeysController } from './api-keys.controller';
import { ApiKeysService } from './api-keys.service';

describe('ApiKeysController', () => {
  let controller: ApiKeysController;
  let service: {
    findAll: jest.Mock;
    create: jest.Mock;
    revoke: jest.Mock;
    remove: jest.Mock;
  };

  const mockUser: AuthUser = {
    id: 'user-1',
    organizationId: 'org-1',
    email: 'admin@example.com',
    fullName: 'Admin',
    role: 'ADMIN',
  };

  beforeEach(async () => {
    service = {
      findAll: jest.fn(),
      create: jest.fn(),
      revoke: jest.fn(),
      remove: jest.fn(),
    };

    const module: TestingModule = await Test.createTestingModule({
      controllers: [ApiKeysController],
      providers: [{ provide: ApiKeysService, useValue: service }],
    }).compile();

    controller = module.get<ApiKeysController>(ApiKeysController);
  });

  it('findAll debe invocar service.findAll con el tenant del usuario', async () => {
    service.findAll.mockResolvedValue([]);
    const res = await controller.findAll(mockUser);
    expect(res).toEqual([]);
    expect(service.findAll).toHaveBeenCalledWith('org-1');
  });

  it('create debe delegar en el servicio', async () => {
    const dto = { name: 'Splunk Key' };
    service.create.mockResolvedValue({ id: 'k-1', rawKey: 'sspm_live_xxx' });
    const res = await controller.create(mockUser, dto);
    expect(res).toEqual({ id: 'k-1', rawKey: 'sspm_live_xxx' });
    expect(service.create).toHaveBeenCalledWith(mockUser, dto);
  });

  it('revoke debe delegar en el servicio', async () => {
    service.revoke.mockResolvedValue({ id: 'k-1', isActive: false });
    const res = await controller.revoke(mockUser, 'k-1');
    expect(res).toEqual({ id: 'k-1', isActive: false });
    expect(service.revoke).toHaveBeenCalledWith(mockUser, 'k-1');
  });

  it('remove debe invocar service.remove', async () => {
    service.remove.mockResolvedValue({ success: true });
    await controller.remove(mockUser, 'k-1');
    expect(service.remove).toHaveBeenCalledWith(mockUser, 'k-1');
  });
});
