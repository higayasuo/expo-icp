import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildQueryString } from '../buildQueryString';
import { buildDelegationString } from '../buildDelegationString';
import { DelegationIdentity } from '@dfinity/identity';

// Mock the buildDelegationString function
vi.mock('../buildDelegationString', () => ({
  buildDelegationString: vi.fn(),
}));

describe('buildQueryString', () => {
  const mockDelegationString = 'test-delegation-string';
  const mockDelegationIdentity = {
    sign: vi.fn(),
  } as unknown as DelegationIdentity;

  beforeEach(() => {
    vi.clearAllMocks();
    (
      buildDelegationString as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(mockDelegationString);
  });

  it('should build a query string with encoded delegation', () => {
    const result = buildQueryString(mockDelegationIdentity);

    expect(result).toBe(
      `delegation=${encodeURIComponent(mockDelegationString)}`,
    );
    expect(buildDelegationString).toHaveBeenCalledWith(mockDelegationIdentity);
  });

  it('should properly encode special characters in the delegation string', () => {
    const specialCharsString = 'test&delegation=string';
    (
      buildDelegationString as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(specialCharsString);

    const result = buildQueryString(mockDelegationIdentity);

    expect(result).toBe(`delegation=${encodeURIComponent(specialCharsString)}`);
  });
});
