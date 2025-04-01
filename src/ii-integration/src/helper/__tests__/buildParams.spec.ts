import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildParams } from '../buildParams';
import { buildAppPublicKey } from '../buildAppPublicKey';
import { buildIIUri } from '../buildIIUri';
import { buildDeepLink } from '../buildDeepLink';
import {
  LOCAL_IP_ADDRESS,
  DFX_NETWORK,
  CANISTER_ID_INTERNET_IDENTITY,
  CANISTER_ID_FRONTEND,
  EXPO_SCHEME,
} from '../../env.generated';

// Mock the helper functions
vi.mock('../buildAppPublicKey', () => ({
  buildAppPublicKey: vi.fn(),
}));

vi.mock('../buildIIUri', () => ({
  buildIIUri: vi.fn(),
}));

vi.mock('../buildDeepLink', () => ({
  buildDeepLink: vi.fn(),
}));

describe('buildParams', () => {
  const mockPublicKey = { toDer: vi.fn() };
  const mockIIUri = 'https://internetcomputer.org';
  const mockDeepLink = 'https://example.com';

  const defaultArgs = {
    localIPAddress: LOCAL_IP_ADDRESS,
    dfxNetwork: DFX_NETWORK,
    internetIdentityCanisterId: CANISTER_ID_INTERNET_IDENTITY,
    frontendCanisterId: CANISTER_ID_FRONTEND,
    expoScheme: EXPO_SCHEME,
  };

  beforeEach(() => {
    // Reset all mocks before each test
    vi.clearAllMocks();

    // Setup default mock implementations
    (buildAppPublicKey as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockPublicKey,
    );
    (buildIIUri as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockIIUri,
    );
    (buildDeepLink as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockDeepLink,
    );

    // Mock window.location
    const location = new URL(
      'https://example.com?pubkey=test-pubkey&deep-link-type=icp',
    );
    vi.stubGlobal('window', {
      location,
    });
  });

  it('should successfully build params with valid query parameters', () => {
    const result = buildParams(defaultArgs);

    expect(result).toEqual({
      appPublicKey: mockPublicKey,
      iiUri: mockIIUri,
      deepLink: mockDeepLink,
    });

    expect(buildAppPublicKey).toHaveBeenCalledWith('test-pubkey');
    expect(buildIIUri).toHaveBeenCalledWith({
      localIPAddress: defaultArgs.localIPAddress,
      dfxNetwork: defaultArgs.dfxNetwork,
      internetIdentityCanisterId: defaultArgs.internetIdentityCanisterId,
    });
    expect(buildDeepLink).toHaveBeenCalledWith({
      deepLinkType: 'icp',
      localIPAddress: defaultArgs.localIPAddress,
      dfxNetwork: defaultArgs.dfxNetwork,
      frontendCanisterId: defaultArgs.frontendCanisterId,
      expoScheme: defaultArgs.expoScheme,
    });
  });

  it('should throw error when pubkey is missing', () => {
    const location = new URL('https://example.com?deep-link-type=icp');
    vi.stubGlobal('window', { location });

    expect(() => buildParams(defaultArgs)).toThrow(
      'Missing pubkey or deep-link-type in query string',
    );
  });

  it('should throw error when deep-link-type is missing', () => {
    const location = new URL('https://example.com?pubkey=test-pubkey');
    vi.stubGlobal('window', { location });

    expect(() => buildParams(defaultArgs)).toThrow(
      'Missing pubkey or deep-link-type in query string',
    );
  });

  it('should throw error when deep-link-type is invalid', () => {
    const location = new URL(
      'https://example.com?pubkey=test-pubkey&deep-link-type=invalid-type',
    );
    vi.stubGlobal('window', { location });

    expect(() => buildParams(defaultArgs)).toThrow(
      'Invalid deep-link-type: invalid-type',
    );
  });
});
