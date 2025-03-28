import { describe, it, expect } from 'vitest';
import { DelegationIdentity } from '@dfinity/identity';
import { buildDelegationString } from '../buildDelegationString';

describe('buildDelegationString', () => {
  it('should convert DelegationIdentity to JSON string', () => {
    const mockDelegationIdentity = {
      getDelegation: () => ({
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
      }),
    } as unknown as DelegationIdentity;
    const result = buildDelegationString(mockDelegationIdentity);

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
