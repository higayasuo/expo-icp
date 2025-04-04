import { DelegationChain } from '@dfinity/identity';
import { describe, it, expect, vi } from 'vitest';
import { sendDelegationToParent } from '../sendDelegationToParent';
import { buildDelegationString } from '../buildDelegationString';

// Mock buildDelegationString
vi.mock('../buildDelegationString', () => ({
  buildDelegationString: vi.fn().mockReturnValue('mocked-delegation-string'),
}));

describe('sendDelegationToParent', () => {
  it('should send delegation to parent window with correct message and origin', () => {
    // Setup
    const mockDeepLink = 'https://example.com/callback';
    const mockDelegationChain = {} as DelegationChain;
    const mockPostMessage = vi.fn();
    const mockWindow = {
      parent: {
        postMessage: mockPostMessage,
      },
      console: {
        log: vi.fn(),
      },
    } as unknown as Window & typeof globalThis;

    // Execute
    sendDelegationToParent({
      deepLink: mockDeepLink,
      delegationChain: mockDelegationChain,
      window: mockWindow,
    });

    // Verify
    expect(buildDelegationString).toHaveBeenCalledWith(mockDelegationChain);
    expect(mockPostMessage).toHaveBeenCalledWith(
      {
        kind: 'success',
        delegation: 'mocked-delegation-string',
      },
      'https://example.com',
    );
  });
});
