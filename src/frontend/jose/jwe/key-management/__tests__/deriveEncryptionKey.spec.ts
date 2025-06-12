import { describe, it, expect, vi } from 'vitest';
import type {
  DeriveEncryptionKeyParams,
  DeriveEncryptionKeyResult,
} from '../deriveEncryptionKey';
import { deriveEncryptionKey } from '../deriveEncryptionKey';
import { ecdhesDeriveEncryptionKey } from '../ecdhesDeriveEncryptKey';
import { JweNotSupported } from '@/jose/errors/errors';

vi.mock('../ecdhesDeriveEncryptKey', () => {
  const fakeResult: DeriveEncryptionKeyResult = {
    cek: new Uint8Array([1, 2, 3]),
    encryptedKey: undefined,
    parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
  };
  return {
    ecdhesDeriveEncryptionKey: vi.fn(() => fakeResult),
  };
});

describe('deriveEncryptionKey', () => {
  it('should delegate to ecdhesDeriveEncryptionKey for ECDH-ES', () => {
    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    const result = deriveEncryptionKey(params);
    expect(ecdhesDeriveEncryptionKey).toHaveBeenCalledWith(params);
    expect(result).toEqual({
      cek: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    });
  });

  it('should delegate to ecdhesDeriveEncryptionKey for ECDH-ES without myPrivateKey', () => {
    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    const result = deriveEncryptionKey(params);
    expect(ecdhesDeriveEncryptionKey).toHaveBeenCalledWith(params);
    expect(result).toEqual({
      cek: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      parameters: { epk: { kty: 'EC', crv: 'P-256', x: 'x', y: 'y' } },
    });
  });

  it('should throw JweNotSupported for unsupported algorithms', () => {
    const params: DeriveEncryptionKeyParams = {
      alg: 'RSA-OAEP' as any,
      enc: 'A256GCM',
      curve: {} as any,
      yourPublicKey: new Uint8Array([2]),
      providedParameters: {},
    };
    expect(() => deriveEncryptionKey(params)).toThrow(JweNotSupported);
  });
});
