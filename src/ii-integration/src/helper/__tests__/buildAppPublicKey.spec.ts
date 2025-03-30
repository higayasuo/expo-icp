import { describe, it, expect, vi, beforeEach } from 'vitest';
import { buildAppPublicKey } from '../buildAppPublicKey';
import { Ed25519PublicKey } from '@dfinity/identity';
import { fromHex } from '@dfinity/agent';

// Mock the dependencies
vi.mock('@dfinity/identity', () => ({
  Ed25519PublicKey: {
    fromDer: vi.fn(),
  },
}));

vi.mock('@dfinity/agent', () => ({
  fromHex: vi.fn(),
}));

describe('buildAppPublicKey', () => {
  const mockHexString =
    '302a300506032b6570032100d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a';
  const mockDerBytes = new Uint8Array([
    48, 42, 48, 5, 6, 3, 43, 101, 112, 3, 33, 0, 215, 90, 152, 1, 130, 177, 10,
    183, 213, 75, 254, 211, 201, 100, 7, 58, 14, 225, 114, 243, 218, 166, 35,
    37, 175, 2, 26, 104, 247, 7, 81, 26,
  ]);
  const mockPublicKey = {
    toDer: vi.fn(),
  };

  beforeEach(() => {
    vi.clearAllMocks();
    (fromHex as unknown as ReturnType<typeof vi.fn>).mockReturnValue(
      mockDerBytes,
    );
    (
      Ed25519PublicKey.fromDer as unknown as ReturnType<typeof vi.fn>
    ).mockReturnValue(mockPublicKey);
  });

  it('should convert a valid Ed25519 public key hex string to Ed25519PublicKey', () => {
    const result = buildAppPublicKey(mockHexString);

    expect(fromHex).toHaveBeenCalledWith(mockHexString);
    expect(Ed25519PublicKey.fromDer).toHaveBeenCalledWith(mockDerBytes);
    expect(result).toBe(mockPublicKey);
  });
});
