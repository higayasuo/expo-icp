import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildParams } from '../buildParams';
import { buildAppPublicKey } from '../buildAppPublicKey';
import { buildIIUri } from '../buildIIUri';
import { buildRedirectUri } from '../buildRedirectUri';

// Mock the helper functions
vi.mock('../buildAppPublicKey', () => ({
  buildAppPublicKey: vi.fn(),
}));

vi.mock('../buildIIUri', () => ({
  buildIIUri: vi.fn(),
}));

vi.mock('../buildRedirectUri', () => ({
  buildRedirectUri: vi.fn(),
}));

describe('buildParams', () => {
  const mockPublicKey = { toDer: vi.fn() };
  const mockIIUri = 'https://internetcomputer.org';
  const mockRedirectUri = 'https://example.com';

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
    (buildRedirectUri as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockRedirectUri,
    );

    // Mock window.location
    const location = new URL(
      'https://example.com?pubkey=test-pubkey&environment=test-env',
    );
    vi.stubGlobal('window', {
      location,
    });
  });

  it('should successfully build params with valid query parameters', () => {
    const result = buildParams();

    expect(result).toEqual({
      appPublicKey: mockPublicKey,
      iiUri: mockIIUri,
      redirectUri: mockRedirectUri,
    });

    expect(buildAppPublicKey).toHaveBeenCalledWith('test-pubkey');
    expect(buildIIUri).toHaveBeenCalled();
    expect(buildRedirectUri).toHaveBeenCalledWith('test-env');
  });

  it('should throw error when pubkey is missing', () => {
    const location = new URL('https://example.com?environment=test-env');
    vi.stubGlobal('window', { location });

    expect(() => buildParams()).toThrow(
      'Missing pubkey or environment in query string',
    );
  });

  it('should throw error when environment is missing', () => {
    const location = new URL('https://example.com?pubkey=test-pubkey');
    vi.stubGlobal('window', { location });

    expect(() => buildParams()).toThrow(
      'Missing pubkey or environment in query string',
    );
  });
});
