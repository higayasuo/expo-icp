import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildMiddleToAppDelegationChain } from '../buildMiddleToAppDelegationChain';
import { DelegationChain, DelegationIdentity } from '@dfinity/identity';
import { PublicKey } from '@dfinity/agent';

// Mock the dependencies
vi.mock('@dfinity/identity', () => ({
  DelegationChain: {
    create: vi.fn(),
  },
  DelegationIdentity: vi.fn(),
}));

describe('buildMiddleToAppDelegationChain', () => {
  const mockDelegationChain = {
    toJSON: vi.fn(),
  };

  const mockDelegation = {
    toJSON: vi.fn(),
  };

  const mockMiddleDelegationIdentity = {
    getPublicKey: vi.fn(),
    getDelegation: vi.fn().mockReturnValue(mockDelegation),
  } as unknown as DelegationIdentity;

  const mockAppPublicKey = {
    toDer: vi.fn(),
  } as unknown as PublicKey;

  beforeEach(() => {
    vi.clearAllMocks();
    (
      DelegationChain.create as unknown as ReturnType<typeof vi.fn>
    ).mockResolvedValue(mockDelegationChain);
  });

  it('should create a delegation chain with the correct parameters', async () => {
    const expiration = new Date();
    const result = await buildMiddleToAppDelegationChain({
      middleDelegationIdentity: mockMiddleDelegationIdentity,
      appPublicKey: mockAppPublicKey,
      expiration,
    });

    expect(DelegationChain.create).toHaveBeenCalledWith(
      mockMiddleDelegationIdentity,
      mockAppPublicKey,
      expiration,
      {
        previous: mockDelegation,
      },
    );
    expect(result).toBe(mockDelegationChain);
  });

  it('should set delegation expiration to 15 minutes from now', async () => {
    const now = Date.now();
    vi.setSystemTime(now);

    const expiration = new Date(now + 1000 * 60 * 15);
    await buildMiddleToAppDelegationChain({
      middleDelegationIdentity: mockMiddleDelegationIdentity,
      appPublicKey: mockAppPublicKey,
      expiration,
    });

    expect(DelegationChain.create).toHaveBeenCalledWith(
      mockMiddleDelegationIdentity,
      mockAppPublicKey,
      expiration,
      {
        previous: mockDelegation,
      },
    );
  });
});
