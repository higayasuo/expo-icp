import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildQueryString } from '../buildQueryString';
import { buildDelegationString } from '../buildDelegationString';
// Mock the buildDelegationString function
vi.mock('../buildDelegationString', () => ({
    buildDelegationString: vi.fn(),
}));
describe('buildQueryString', () => {
    const mockDelegationString = 'test-delegation-string';
    const mockDelegationIdentity = {
        sign: vi.fn(),
    };
    beforeEach(() => {
        vi.clearAllMocks();
        buildDelegationString.mockReturnValue(mockDelegationString);
    });
    it('should build a query string with encoded delegation', () => {
        const result = buildQueryString(mockDelegationIdentity);
        expect(result).toBe(`delegation=${encodeURIComponent(mockDelegationString)}`);
        expect(buildDelegationString).toHaveBeenCalledWith(mockDelegationIdentity);
    });
    it('should properly encode special characters in the delegation string', () => {
        const specialCharsString = 'test&delegation=string';
        buildDelegationString.mockReturnValue(specialCharsString);
        const result = buildQueryString(mockDelegationIdentity);
        expect(result).toBe(`delegation=${encodeURIComponent(specialCharsString)}`);
    });
});
