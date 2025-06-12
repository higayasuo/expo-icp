import { describe, it, expect, vi } from 'vitest';
import { deriveDecryptionKey } from '../deriveDecryptionKey';
import type { ManageDecryptKeyParams } from '../deriveDecryptionKey';
import * as ecdhesManageDecryptKeyModule from '../ecdhesDriveDecryptionKey';

describe('manageDecryptKey', () => {
  it('should call ecdhesManageDecryptKey for ECDH-ES', () => {
    const mockCek = new Uint8Array([1, 2, 3, 4]);
    vi.spyOn(
      ecdhesManageDecryptKeyModule,
      'ecdhesManageDecryptKey',
    ).mockReturnValue(mockCek);

    const params: ManageDecryptKeyParams = {
      alg: 'ECDH-ES',
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
      ecdhesManageDecryptKeyModule.ecdhesDeriveDecryptionKey,
    ).toHaveBeenCalledWith(params);
    expect(result).toBe(mockCek);
  });

  it('should throw error for unsupported algorithm', () => {
    const params: ManageDecryptKeyParams = {
      alg: 'RSA-OAEP' as any,
      curve: {} as any,
      myPrivateKey: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'RSA-OAEP' as any,
        enc: 'A256GCM',
      },
    };

    expect(() => deriveDecryptionKey(params)).toThrow(
      'Unsupported JWE Algorithm: RSA-OAEP',
    );
  });
});
