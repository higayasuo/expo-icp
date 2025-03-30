import { vi, describe, it, expect, beforeEach } from 'vitest';
import { AuthClient } from '@dfinity/auth-client';
import { DelegationIdentity } from '@dfinity/identity';
import { PublicKey } from '@dfinity/agent';
import { prepareLogin } from '../prepareLogin';
import { processDelegation } from '../processDelegation';

vi.mock('@dfinity/auth-client');
vi.mock('@dfinity/identity');
vi.mock('../processDelegation');

describe('prepareLogin', () => {
  const mockPublicKey = {} as PublicKey;
  const mockArgs = {
    appPublicKey: mockPublicKey,
    iiUri: 'https://test.ic0.app',
    redirectUri: 'https://test.app/callback',
  };

  const mockAuthClient = {
    login: vi.fn(),
    getIdentity: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (
      AuthClient.create as unknown as ReturnType<typeof vi.fn>
    ).mockResolvedValue(mockAuthClient);
  });

  it('should return a function that handles login process', async () => {
    const loginFunction = await prepareLogin(mockArgs);
    expect(typeof loginFunction).toBe('function');
  });

  it('should process delegation on successful login', async () => {
    const mockDelegationIdentity = {} as DelegationIdentity;
    mockAuthClient.getIdentity.mockReturnValue(mockDelegationIdentity);
    mockAuthClient.login.mockImplementation(({ onSuccess }) => {
      onSuccess();
    });

    const loginFunction = await prepareLogin(mockArgs);
    await loginFunction();

    expect(processDelegation).toHaveBeenCalledWith({
      redirectUri: mockArgs.redirectUri,
      middleDelegationIdentity: mockDelegationIdentity,
      appPublicKey: mockArgs.appPublicKey,
      expiration: expect.any(Date),
    });
  });

  it('should throw error on login failure', async () => {
    const errorMessage = 'Login failed';
    mockAuthClient.login.mockImplementation(({ onError }) => {
      onError(errorMessage);
    });

    const loginFunction = await prepareLogin(mockArgs);

    await expect(loginFunction()).rejects.toThrow(errorMessage);
  });

  it('should use default expiration time if not provided', async () => {
    const mockDelegationIdentity = {} as DelegationIdentity;
    mockAuthClient.getIdentity.mockReturnValue(mockDelegationIdentity);
    mockAuthClient.login.mockImplementation(({ onSuccess }) => {
      onSuccess();
    });

    const loginFunction = await prepareLogin(mockArgs);
    await loginFunction();

    const callArgs = (processDelegation as unknown as ReturnType<typeof vi.fn>)
      .mock.calls[0][0];
    const expiration = callArgs.expiration as Date;
    const now = new Date();
    const diffInMinutes = (expiration.getTime() - now.getTime()) / (1000 * 60);

    expect(diffInMinutes).toBeCloseTo(15, 0); // Should be approximately 15 minutes
  });
});
