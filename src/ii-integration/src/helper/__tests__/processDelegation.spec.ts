import { describe, it, expect, vi, beforeEach } from 'vitest';
import { processDelegation } from '../processDelegation';
import { buildDelegationString } from '../buildDelegationString';
import { buildQueryString } from '../buildQueryString';
import { DelegationIdentity } from '@dfinity/identity';

// Mock the helper functions
vi.mock('../buildDelegationString', () => ({
  buildDelegationString: vi.fn(),
}));

vi.mock('../buildQueryString', () => ({
  buildQueryString: vi.fn(),
}));

describe('processDelegation', () => {
  const mockDelegationIdentity = {
    sign: vi.fn(),
  } as unknown as DelegationIdentity;

  const mockRedirectUri = 'https://example.com/';
  const mockDelegationString = 'mock-delegation-string';
  const mockQueryString = 'delegation=mock-query-string';

  beforeEach(() => {
    vi.clearAllMocks();
    (
      buildDelegationString as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(mockDelegationString);
    (buildQueryString as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockQueryString,
    );
  });

  it('should use postMessage when in an iframe', () => {
    // Mock iframe environment
    const mockParent = { postMessage: vi.fn() };
    const mockWindow = {
      location: new URL(mockRedirectUri),
      parent: mockParent,
      postMessage: vi.fn(),
    };
    vi.stubGlobal('window', mockWindow);

    processDelegation({
      redirectUri: mockRedirectUri,
      delegationIdentity: mockDelegationIdentity,
    });

    expect(buildDelegationString).toHaveBeenCalledWith(mockDelegationIdentity);
    expect(mockParent.postMessage).toHaveBeenCalledWith(
      {
        kind: 'success',
        delegation: mockDelegationString,
      },
      new URL(mockRedirectUri).origin,
    );
  });

  it('should use URL redirection when not in an iframe', () => {
    // Mock native app environment
    const mockWindow = {
      location: new URL(mockRedirectUri),
      postMessage: vi.fn(),
    };
    // Create a new mock window with parent set to itself
    const nonIframeWindow = {
      ...mockWindow,
      parent: mockWindow,
    };
    // Override the window.parent check to simulate non-iframe environment
    Object.defineProperty(nonIframeWindow, 'parent', {
      get: () => nonIframeWindow,
    });
    vi.stubGlobal('window', nonIframeWindow);

    processDelegation({
      redirectUri: mockRedirectUri,
      delegationIdentity: mockDelegationIdentity,
    });

    expect(buildQueryString).toHaveBeenCalledWith(mockDelegationIdentity);
    const expectedUrl = new URL(mockRedirectUri);
    expectedUrl.hash = mockQueryString;
    expect(nonIframeWindow.location.href).toBe(expectedUrl.toString());
  });
});
