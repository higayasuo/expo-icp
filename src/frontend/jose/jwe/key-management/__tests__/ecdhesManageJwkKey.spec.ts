import { describe, it, expect, vi } from 'vitest';
import { ecdhesManageJwkKey } from '../ecdhesManageJwkKey';
import type { ManageJwkKeyParams } from '../manageJwkKey';
import type { Jwk } from '@/jose/types';

const fakeCurve = {
  getPublicKey: vi.fn(() => new Uint8Array([1, 2, 3, 4])),
  toJwkPublicKey: vi.fn(
    (pub: Uint8Array) =>
      ({
        kty: 'EC',
        crv: 'P-256',
        x: 'x-coord',
        y: 'y-coord',
      } as Jwk),
  ),
  getSharedSecret: vi.fn(
    () => new Uint8Array([0, 11, 22, 33, 44, 55, 66, 77, 88, 99]),
  ),
};

vi.mock('@/jose/ecdhes/buildKdfOtherInfo', () => ({
  buildKdfOtherInfo: vi.fn(() => new Uint8Array([9, 9, 9])),
}));
vi.mock('../utils/keyBitLengthByEnc', () => ({
  keyBitLengthByEnc: vi.fn(() => 128),
}));
vi.mock('@/jose/ecdhes/concatKdf', () => ({
  concatKdf: vi.fn(() => new Uint8Array([42, 42, 42, 42])),
}));
vi.mock('u8a-utils', () => ({
  toB64U: vi.fn((u: Uint8Array) => 'b64u-' + Array.from(u).join('-')),
}));

describe('ecdhesManageJwkKey', () => {
  it('should return correct CEK, undefined encryptedKey, and header parameters with apu/apv', () => {
    const params: ManageJwkKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: fakeCurve as any,
      privateKey: new Uint8Array([10, 20, 30, 40]),
      publicKey: new Uint8Array([50, 60, 70, 80]),
      providedParameters: {
        apu: new Uint8Array([1, 2, 3]),
        apv: new Uint8Array([4, 5, 6]),
      },
    };
    const result = ecdhesManageJwkKey(params);
    expect(result.cek).toEqual(new Uint8Array([42, 42, 42, 42]));
    expect(result.encryptedKey).toBeUndefined();
    expect(result.parameters).toEqual({
      epk: { kty: 'EC', crv: 'P-256', x: 'x-coord', y: 'y-coord' },
      apu: 'b64u-1-2-3',
      apv: 'b64u-4-5-6',
    });
  });

  it('should omit apu/apv if not provided', () => {
    const params: ManageJwkKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: fakeCurve as any,
      privateKey: new Uint8Array([10, 20, 30, 40]),
      publicKey: new Uint8Array([50, 60, 70, 80]),
      providedParameters: {},
    };
    const result = ecdhesManageJwkKey(params);
    expect(result.parameters).toEqual({
      epk: { kty: 'EC', crv: 'P-256', x: 'x-coord', y: 'y-coord' },
    });
  });
});
