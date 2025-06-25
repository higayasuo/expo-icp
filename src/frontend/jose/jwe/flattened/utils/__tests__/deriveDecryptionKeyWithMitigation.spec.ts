import { describe, it, expect, vi, beforeEach } from 'vitest';
import { deriveDecryptionKeyWithMitigation } from '../deriveDecryptionKeyWithMitigation';
import { deriveDecryptionKey } from '@/jose/jwe/key-management/deriveDecryptionKey';
import { generateMitigatedCek } from '../generateMitigatedCek';
import { createEcdhCurve } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { JweInvalid, JoseNotSupported } from '@/jose/errors/errors';

const { getRandomBytes } = webCryptoModule;
const curve = createEcdhCurve('P-256', getRandomBytes);

vi.mock('@/jose/jwe/key-management/deriveDecryptionKey');
vi.mock('../generateMitigatedCek');

describe('deriveDecryptionKeyWithMitigation', () => {
  const mockParams = {
    alg: 'ECDH-ES' as const,
    enc: 'A256GCM' as const,
    curve,
    myPrivateKey: new Uint8Array(32),
    encryptedKey: new Uint8Array(32),
    protectedHeader: { alg: 'ECDH-ES' as const, enc: 'A256GCM' as const },
  };

  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should return derived key when key derivation succeeds', async () => {
    const expectedKey = new Uint8Array(32);
    vi.mocked(deriveDecryptionKey).mockResolvedValue(expectedKey);

    const result = await deriveDecryptionKeyWithMitigation(mockParams);

    expect(result).toBe(expectedKey);
    expect(deriveDecryptionKey).toHaveBeenCalledWith(mockParams);
    expect(generateMitigatedCek).not.toHaveBeenCalled();
  });

  it('should generate mitigated CEK when key derivation fails', async () => {
    const expectedKey = new Uint8Array(32);
    vi.mocked(deriveDecryptionKey).mockImplementation(() => {
      throw new Error('Key derivation failed');
    });
    vi.mocked(generateMitigatedCek).mockResolvedValue(expectedKey);

    const result = await deriveDecryptionKeyWithMitigation(mockParams);

    expect(result).toBe(expectedKey);
    expect(deriveDecryptionKey).toHaveBeenCalledWith(mockParams);
    expect(generateMitigatedCek).toHaveBeenCalledWith(
      mockParams.curve,
      mockParams.enc,
    );
  });

  it('should handle JweInvalid error from key derivation', async () => {
    const expectedKey = new Uint8Array(32);
    vi.mocked(deriveDecryptionKey).mockImplementation(() => {
      throw new JweInvalid('Invalid header');
    });
    vi.mocked(generateMitigatedCek).mockResolvedValue(expectedKey);

    const result = await deriveDecryptionKeyWithMitigation(mockParams);

    expect(result).toBe(expectedKey);
    expect(deriveDecryptionKey).toHaveBeenCalledWith(mockParams);
    expect(generateMitigatedCek).toHaveBeenCalledWith(
      mockParams.curve,
      mockParams.enc,
    );
  });

  it('should handle JoseNotSupported error from key derivation', async () => {
    const expectedKey = new Uint8Array(32);
    vi.mocked(deriveDecryptionKey).mockImplementation(() => {
      throw new JoseNotSupported('Unsupported algorithm');
    });
    vi.mocked(generateMitigatedCek).mockResolvedValue(expectedKey);

    const result = await deriveDecryptionKeyWithMitigation(mockParams);

    expect(result).toBe(expectedKey);
    expect(deriveDecryptionKey).toHaveBeenCalledWith(mockParams);
    expect(generateMitigatedCek).toHaveBeenCalledWith(
      mockParams.curve,
      mockParams.enc,
    );
  });
});
