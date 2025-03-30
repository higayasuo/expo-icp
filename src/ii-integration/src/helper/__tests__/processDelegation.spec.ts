import { describe, it, expect, vi, beforeEach } from 'vitest';
import { processDelegation } from '../processDelegation';
import { buildDelegationString } from '../buildDelegationString';
import { buildURIFragment } from '../buildURIFragment';
import { buildMiddleToAppDelegationChain } from '../buildMiddleToAppDelegationChain';
import { DelegationIdentity, DelegationChain } from '@dfinity/identity';
import { PublicKey } from '@dfinity/agent';

// Mock the helper functions
vi.mock('../buildDelegationString', () => ({
  buildDelegationString: vi.fn(),
}));

vi.mock('../buildURIFragment', () => ({
  buildURIFragment: vi.fn(),
}));

vi.mock('../buildMiddleToAppDelegationChain', () => ({
  buildMiddleToAppDelegationChain: vi.fn(),
}));

// Mock global window
const mockPostMessage = vi.fn();
const mockLocation = {
  href: '',
  origin: '',
};

const mockWindow = {
  postMessage: mockPostMessage,
  location: mockLocation,
} as unknown as Window;

vi.stubGlobal('window', mockWindow);

describe('processDelegation', () => {
  const mockDelegationIdentity = {
    sign: vi.fn(),
    getDelegation: vi.fn(),
  } as unknown as DelegationIdentity;

  const mockDelegationChain = {
    toJSON: vi.fn(),
  } as unknown as DelegationChain;

  const mockAppPublicKey = {
    toDer: vi.fn(),
  } as unknown as PublicKey;

  const mockRedirectUri = 'https://example.com/';
  const mockDelegationString = 'mock-delegation-string';
  const mockUriFragment = 'delegation=mock-uri-fragment';
  const mockExpiration = new Date();

  beforeEach(() => {
    vi.clearAllMocks();
    mockPostMessage.mockClear();
    mockLocation.href = '';
    (
      buildDelegationString as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(mockDelegationString);
    (buildURIFragment as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockUriFragment,
    );
    (
      buildMiddleToAppDelegationChain as unknown as ReturnType<typeof vi.fn>
    ).mockResolvedValue(mockDelegationChain);
  });

  it('should use postMessage when in an iframe', async () => {
    // Mock iframe environment
    const mockParent = { postMessage: vi.fn() };
    Object.defineProperty(mockWindow, 'parent', {
      get: () => mockParent,
    });
    mockLocation.origin = new URL(mockRedirectUri).origin;

    await processDelegation({
      redirectUri: mockRedirectUri,
      middleDelegationIdentity: mockDelegationIdentity,
      appPublicKey: mockAppPublicKey,
      expiration: mockExpiration,
    });

    expect(buildMiddleToAppDelegationChain).toHaveBeenCalledWith({
      middleDelegationIdentity: mockDelegationIdentity,
      appPublicKey: mockAppPublicKey,
      expiration: mockExpiration,
    });
    expect(buildDelegationString).toHaveBeenCalledWith(mockDelegationChain);
    expect(mockParent.postMessage).toHaveBeenCalledWith(
      {
        kind: 'success',
        delegation: mockDelegationString,
      },
      new URL(mockRedirectUri).origin,
    );
  });

  it('should use URL redirection when not in an iframe', async () => {
    // Mock native app environment
    const mockLocation = {
      href: '',
      origin: '',
    };
    const mockWindow = {
      postMessage: vi.fn(),
      location: mockLocation,
    } as unknown as Window;
    Object.defineProperty(mockWindow, 'parent', {
      get: () => mockWindow,
    });

    vi.stubGlobal('window', mockWindow);

    await processDelegation({
      redirectUri: mockRedirectUri,
      middleDelegationIdentity: mockDelegationIdentity,
      appPublicKey: mockAppPublicKey,
      expiration: mockExpiration,
    });

    expect(buildMiddleToAppDelegationChain).toHaveBeenCalledWith({
      middleDelegationIdentity: mockDelegationIdentity,
      appPublicKey: mockAppPublicKey,
      expiration: mockExpiration,
    });
    expect(buildURIFragment).toHaveBeenCalledWith(mockDelegationChain);
    expect(mockWindow.location.href).toBe(
      `${mockRedirectUri}#${mockUriFragment}`,
    );
  });
});
