import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildURIFragment } from '../buildURIFragment';
import { buildDelegationString } from '../buildDelegationString';
import { DelegationChain } from '@dfinity/identity';

// Mock the buildDelegationString function
vi.mock('../buildDelegationString', () => ({
  buildDelegationString: vi.fn(),
}));

describe('buildURIFragment', () => {
  const mockDelegationChain = {
    toJSON: vi.fn(),
  } as unknown as DelegationChain;

  const mockDelegationString = 'mock-delegation-string';
  const mockEncodedDelegation = 'mock-encoded-delegation';

  beforeEach(() => {
    vi.clearAllMocks();
    (
      buildDelegationString as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(mockDelegationString);
    vi.spyOn(global, 'encodeURIComponent').mockReturnValue(
      mockEncodedDelegation,
    );
  });

  it('should build a URI fragment with the encoded delegation string', () => {
    const result = buildURIFragment(mockDelegationChain);

    expect(buildDelegationString).toHaveBeenCalledWith(mockDelegationChain);
    expect(global.encodeURIComponent).toHaveBeenCalledWith(
      mockDelegationString,
    );
    expect(result).toBe(`delegation=${mockEncodedDelegation}`);
  });
});
