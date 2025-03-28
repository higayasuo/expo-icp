import { describe, it, expect, vi } from 'vitest';
import { buildIIUri } from '../buildIIUri';
import { CanisterManager } from 'canister-manager';
import { LOCAL_IP_ADDRESS, DFX_NETWORK, CANISTER_ID_INTERNET_IDENTITY, } from '../../env.generated';
vi.mock('canister-manager', () => {
    return {
        CanisterManager: vi.fn().mockImplementation(() => ({
            getInternetIdentityURL: vi
                .fn()
                .mockReturnValue(`http://${LOCAL_IP_ADDRESS}:4943?canisterId=${CANISTER_ID_INTERNET_IDENTITY}`),
        })),
    };
});
describe('buildIIUri', () => {
    it('should return the correct Internet Identity URL', () => {
        const expectedUrl = `http://${LOCAL_IP_ADDRESS}:4943?canisterId=${CANISTER_ID_INTERNET_IDENTITY}`;
        const result = buildIIUri();
        expect(result).toBe(expectedUrl);
    });
    it('should create CanisterManager with correct parameters', () => {
        buildIIUri();
        expect(CanisterManager).toHaveBeenCalledWith({
            localIPAddress: LOCAL_IP_ADDRESS,
            dfxNetwork: DFX_NETWORK,
        });
    });
});
