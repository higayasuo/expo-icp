import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildParams } from '../buildParams';
import { buildIdentity } from '../buildIdentity';
import { buildIIUri } from '../buildIIUri';
import { buildRedirectUri } from '../buildRedirectUri';
// Mock the helper functions
vi.mock('../buildIdentity', () => ({
    buildIdentity: vi.fn(),
}));
vi.mock('../buildIIUri', () => ({
    buildIIUri: vi.fn(),
}));
vi.mock('../buildRedirectUri', () => ({
    buildRedirectUri: vi.fn(),
}));
describe('buildParams', () => {
    const mockIdentity = { sign: vi.fn() };
    const mockIIUri = 'https://internetcomputer.org';
    const mockRedirectUri = 'https://example.com';
    beforeEach(() => {
        // Reset all mocks before each test
        vi.clearAllMocks();
        // Setup default mock implementations
        buildIdentity.mockReturnValue(mockIdentity);
        buildIIUri.mockReturnValue(mockIIUri);
        buildRedirectUri.mockReturnValue(mockRedirectUri);
        // Mock window.location
        const location = new URL('https://example.com?pubkey=test-pubkey&environment=test-env');
        vi.stubGlobal('window', {
            location,
        });
    });
    it('should successfully build params with valid query parameters', () => {
        const result = buildParams();
        expect(result).toEqual({
            identity: mockIdentity,
            iiUri: mockIIUri,
            redirectUri: mockRedirectUri,
        });
        expect(buildIdentity).toHaveBeenCalledWith('test-pubkey');
        expect(buildIIUri).toHaveBeenCalled();
        expect(buildRedirectUri).toHaveBeenCalledWith('test-env');
    });
    it('should throw error when pubkey is missing', () => {
        const location = new URL('https://example.com?environment=test-env');
        vi.stubGlobal('window', { location });
        expect(() => buildParams()).toThrow('Missing pubkey or environment in query string');
    });
    it('should throw error when environment is missing', () => {
        const location = new URL('https://example.com?pubkey=test-pubkey');
        vi.stubGlobal('window', { location });
        expect(() => buildParams()).toThrow('Missing pubkey or environment in query string');
    });
});
