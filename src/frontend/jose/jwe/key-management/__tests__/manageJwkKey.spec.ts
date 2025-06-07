import { describe, it, expect, vi } from 'vitest';
import type { ManageJwkKeyParams, ManageJwkKeyResult } from '../manageJwkKey';
import { manageJwkKey } from '../manageJwkKey';
import { ecdhesManageJwkKey } from '../ecdhesManageJwkKey';

vi.mock('../ecdhesManageJwkKey', () => {
  const fakeResult: ManageJwkKeyResult = {
    cek: new Uint8Array([1, 2, 3]),
    encryptedKey: undefined,
    parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
  };
  return {
    ecdhesManageJwkKey: vi.fn(() => fakeResult),
  };
});

describe('manageJwkKey', () => {
  it('should delegate to ecdhesManageJwkKey for ECDH-ES', () => {
    const params: ManageJwkKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      myPrivateKey: new Uint8Array([1]),
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    const result = manageJwkKey(params);
    expect(ecdhesManageJwkKey).toHaveBeenCalledWith(params);
    expect(result).toEqual({
      cek: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    });
  });

  it('should delegate to ecdhesManageJwkKey for ECDH-ES without myPrivateKey', () => {
    const params: ManageJwkKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    const result = manageJwkKey(params);
    expect(ecdhesManageJwkKey).toHaveBeenCalledWith(params);
    expect(result).toEqual({
      cek: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    });
  });

  it('should throw for unsupported algorithms', () => {
    const params: ManageJwkKeyParams = {
      alg: 'RSA-OAEP',
      enc: 'A256GCM',
      curve: {} as any,
      myPrivateKey: new Uint8Array([1]),
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    expect(() => manageJwkKey(params)).toThrowError(
      'Unsupported JWE Algorithm: RSA-OAEP',
    );
  });
});
