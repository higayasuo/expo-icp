import { describe, it, expect } from 'vitest';
import { DelegationChain } from '@dfinity/identity';
import { buildDelegationString } from '../buildDelegationString';

describe('buildDelegationString', () => {
  it('should convert DelegationChain to JSON string', () => {
    const mockDelegationChain = {
      toJSON: () => ({
        delegations: [
          {
            delegation: {
              pubkey: 'test-pubkey',
              expiration: '1234567890000000',
            },
            signature: 'test-signature',
          },
        ],
        publicKey: 'test-public-key',
      }),
    } as unknown as DelegationChain;

    const result = buildDelegationString(mockDelegationChain);

    const expected = JSON.stringify({
      delegations: [
        {
          delegation: {
            pubkey: 'test-pubkey',
            expiration: '1234567890000000',
          },
          signature: 'test-signature',
        },
      ],
      publicKey: 'test-public-key',
    });

    expect(result).toBe(expected);
  });
});
