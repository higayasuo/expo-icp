import { describe, it, expect, vi, beforeEach } from 'vitest';
import { handleNativeAppDelegation } from '../handleNativeAppDelegation';
import { buildURIFragment } from '../buildURIFragment';
import { DelegationChain } from '@dfinity/identity';

// Mock the helper functions
vi.mock('../buildURIFragment', () => ({
  buildURIFragment: vi.fn(),
}));

describe('handleNativeAppDelegation', () => {
  const mockDelegationChain = {
    toJSON: vi.fn(),
  } as unknown as DelegationChain;

  const mockDeepLink = 'https://example.com/';
  const mockUriFragment = 'delegation=mock-uri-fragment';

  // Mock DOM elements
  const mockLoginButton = {
    style: { display: '' },
  } as unknown as HTMLElement;
  const mockBackToAppButton = {
    style: { display: '' },
    addEventListener: vi.fn(),
  } as unknown as HTMLElement;

  // Mock window object
  const mockOpen = vi.fn();
  const mockWindow = {
    open: mockOpen,
  } as unknown as Window & typeof globalThis;

  beforeEach(() => {
    vi.clearAllMocks();
    (buildURIFragment as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockUriFragment,
    );
  });

  it('should set up UI elements and add click event listener for native app delegation', () => {
    handleNativeAppDelegation({
      deepLink: mockDeepLink,
      delegationChain: mockDelegationChain,
      window: mockWindow,
      iiLoginButton: mockLoginButton,
      backToAppButton: mockBackToAppButton,
    });

    // Verify URI fragment was built
    expect(buildURIFragment).toHaveBeenCalledWith(mockDelegationChain);

    // Verify UI elements were updated
    expect(mockLoginButton.style.display).toBe('none');
    expect(mockBackToAppButton.style.display).toBe('block');

    // Verify click event listener was added
    expect(mockBackToAppButton.addEventListener).toHaveBeenCalledWith(
      'click',
      expect.any(Function),
    );

    // Simulate click event
    const clickCallback = (
      mockBackToAppButton.addEventListener as unknown as ReturnType<
        typeof vi.fn
      >
    ).mock.calls[0][1];
    clickCallback();

    // Verify window.open was called with correct parameters
    expect(mockOpen).toHaveBeenCalledWith(
      `${mockDeepLink}#${mockUriFragment}`,
      '_self',
    );
  });
});
