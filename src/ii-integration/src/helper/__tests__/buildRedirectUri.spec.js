import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildRedirectUri } from '../buildRedirectUri';
import { CanisterManager } from 'canister-manager';
import { LOCAL_IP_ADDRESS, DFX_NETWORK, CANISTER_ID_FRONTEND, } from '../../env.generated';
// Mock the CanisterManager class
const mockGetFrontendCanisterURL = vi
    .fn()
    .mockReturnValue('https://mock-canister-url.ic0.app');
vi.mock('canister-manager', () => ({
    CanisterManager: vi.fn().mockImplementation(() => ({
        getFrontendCanisterURL: mockGetFrontendCanisterURL,
    })),
}));
describe('buildRedirectUri', () => {
    beforeEach(() => {
        vi.clearAllMocks();
    });
    it('should return storeClient redirect URI', () => {
        const result = buildRedirectUri('storeClient');
        expect(result).toBe(`exp://${LOCAL_IP_ADDRESS}:8081/--/`);
    });
    it('should return bare redirect URI', () => {
        const result = buildRedirectUri('bare');
        expect(result).toBe('http://localhost:8081');
    });
    it('should return icp redirect URI using CanisterManager', () => {
        const result = buildRedirectUri('icp');
        expect(CanisterManager).toHaveBeenCalledWith({
            localIPAddress: LOCAL_IP_ADDRESS,
            dfxNetwork: DFX_NETWORK,
        });
        expect(mockGetFrontendCanisterURL).toHaveBeenCalledWith(CANISTER_ID_FRONTEND);
        expect(result).toBe('https://mock-canister-url.ic0.app');
    });
    it('should throw error for unsupported environment', () => {
        expect(() => buildRedirectUri('unsupported')).toThrow('Not supported environment: unsupported');
    });
});
