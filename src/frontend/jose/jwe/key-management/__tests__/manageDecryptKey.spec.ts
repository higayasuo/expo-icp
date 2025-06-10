import { describe, it, expect, vi } from 'vitest';
import { manageDecryptKey } from '../manageDecryptKey';
import type { ManageDecryptKeyParams } from '../manageDecryptKey';
import * as ecdhesManageDecryptKeyModule from '../ecdhesManageDecryptKey';

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

    const result = manageDecryptKey(params);

    expect(
      ecdhesManageDecryptKeyModule.ecdhesManageDecryptKey,
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

    expect(() => manageDecryptKey(params)).toThrow(
      'Unsupported JWE Algorithm: RSA-OAEP',
    );
  });
});
