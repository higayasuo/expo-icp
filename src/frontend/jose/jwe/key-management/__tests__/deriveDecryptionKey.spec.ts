import { describe, it, expect, vi } from 'vitest';
import { deriveDecryptionKey } from '../deriveDecryptionKey';
import type { DeriveDecryptionKeyParams } from '../deriveDecryptionKey';
import * as ecdhesDeriveDecryptionKeyModule from '../ecdhesDriveDecryptionKey';
import { JweNotSupported } from '@/jose/errors/errors';

describe('deriveDecryptionKey', () => {
  it('should call ecdhesDeriveDecryptionKey for ECDH-ES', () => {
    const mockCek = new Uint8Array([1, 2, 3, 4]);
    vi.spyOn(
      ecdhesDeriveDecryptionKeyModule,
      'ecdhesDeriveDecryptionKey',
    ).mockReturnValue(mockCek);

    const params: DeriveDecryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      myPrivateKey: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      },
    };

    const result = deriveDecryptionKey(params);

    expect(
      ecdhesDeriveDecryptionKeyModule.ecdhesDeriveDecryptionKey,
    ).toHaveBeenCalledWith(params);
    expect(result).toBe(mockCek);
  });

  it('should throw error for unsupported algorithm', () => {
    const params: DeriveDecryptionKeyParams = {
      alg: 'RSA-OAEP' as any,
      enc: 'A256GCM',
      curve: {} as any,
      myPrivateKey: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'RSA-OAEP' as any,
        enc: 'A256GCM',
      },
    };

    expect(() => deriveDecryptionKey(params)).toThrow(JweNotSupported);
  });
});
