import { describe, it, expect, vi } from 'vitest';
import type {
  ManageEncryptKeyParams,
  ManageEncryptKeyResult,
} from '../manageEncryptKey';
import { manageEncryptKey } from '../manageEncryptKey';
import { ecdhesManageEncryptKey } from '../ecdhesManageEncryptKey';

vi.mock('../ecdhesManageEncryptKey', () => {
  const fakeResult: ManageEncryptKeyResult = {
    cek: new Uint8Array([1, 2, 3]),
    encryptedKey: undefined,
    parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
  };
  return {
    ecdhesManageEncryptKey: vi.fn(() => fakeResult),
  };
});

describe('manageEncryptKey', () => {
  it('should delegate to ecdhesManageEncryptKey for ECDH-ES', () => {
    const params: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    const result = manageEncryptKey(params);
    expect(ecdhesManageEncryptKey).toHaveBeenCalledWith(params);
    expect(result).toEqual({
      cek: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    });
  });

  it('should delegate to ecdhesManageEncryptKey for ECDH-ES without myPrivateKey', () => {
    const params: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    const result = manageEncryptKey(params);
    expect(ecdhesManageEncryptKey).toHaveBeenCalledWith(params);
    expect(result).toEqual({
      cek: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    });
  });

  it('should throw for unsupported algorithms', () => {
    const params: ManageEncryptKeyParams = {
      alg: 'RSA-OAEP',
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    expect(() => manageEncryptKey(params)).toThrowError(
      'Unsupported JWE Algorithm: RSA-OAEP',
    );
  });
});
