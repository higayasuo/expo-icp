import { describe, it, expect } from 'vitest';
import { ecdhesDeriveEncryptionKey } from '../ecdhesDeriveEncryptKey';
import type { DeriveEncryptionKeyParams } from '../deriveEncryptionKey';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { createNistCurve } from 'noble-curves-extended';
import { encodeBase64Url } from 'u8a-utils';
import { JweInvalid, JweNotSupported } from '@/jose/errors/errors';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);

describe('ecdhesDeriveEncryptionKey', () => {
  it('should return correct CEK, undefined encryptedKey, and header parameters with apu/apv', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const apu = new TextEncoder().encode('Alice');
    const apv = new TextEncoder().encode('Bob');

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apu,
        apv,
      },
    };

    const result = ecdhesDeriveEncryptionKey(params);

    // Verify CEK is a Uint8Array with correct length (256 bits = 32 bytes for A256GCM)
    expect(result.cek).toBeInstanceOf(Uint8Array);
    expect(result.cek.length).toBe(32);

    // Verify encryptedKey is undefined for ECDH-ES
    expect(result.encryptedKey).toBeUndefined();

    // Verify header parameters
    expect(result.parameters).toEqual({
      epk: expect.objectContaining({
        kty: 'EC',
        crv: 'P-256',
        x: expect.any(String),
        y: expect.any(String),
      }),
      apu: encodeBase64Url(apu),
      apv: encodeBase64Url(apv),
    });
    expect(curve.toRawPublicKey(result.parameters.epk!).length).toBe(65);
  });

  it('should omit apu/apv if not provided', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {},
    };

    const result = ecdhesDeriveEncryptionKey(params);

    // Verify CEK is a Uint8Array with correct length
    expect(result.cek).toBeInstanceOf(Uint8Array);
    expect(result.cek.length).toBe(32);

    // Verify encryptedKey is undefined
    expect(result.encryptedKey).toBeUndefined();

    // Verify header parameters only contain epk
    expect(result.parameters).toEqual({
      epk: expect.objectContaining({
        kty: 'EC',
        crv: 'P-256',
        x: expect.any(String),
        y: expect.any(String),
      }),
    });
    expect(curve.toRawPublicKey(result.parameters.epk!).length).toEqual(65);
  });

  it('should generate different CEKs for different key pairs', async () => {
    // Generate two different key pairs
    const rawPrivateKey1 = curve.utils.randomPrivateKey();
    const rawPublicKey1 = curve.getPublicKey(rawPrivateKey1, false);
    const rawPrivateKey2 = curve.utils.randomPrivateKey();
    const rawPublicKey2 = curve.getPublicKey(rawPrivateKey2, false);

    const params1: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey1,
      providedParameters: {},
    };

    const params2: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey2,
      providedParameters: {},
    };

    const result1 = ecdhesDeriveEncryptionKey(params1);
    const result2 = ecdhesDeriveEncryptionKey(params2);

    // Verify CEKs are different
    expect(result1.cek).not.toEqual(result2.cek);
  });

  it('should throw JweInvalid for apu exceeding 32 bytes', async () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const apu = new Uint8Array(33); // 33 bytes

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apu,
      },
    };

    expect(() => ecdhesDeriveEncryptionKey(params)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for apv exceeding 32 bytes', async () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const apv = new Uint8Array(33); // 33 bytes

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apv,
      },
    };

    expect(() => ecdhesDeriveEncryptionKey(params)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for invalid apu type', async () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apu: 'invalid' as any,
      },
    };

    expect(() => ecdhesDeriveEncryptionKey(params)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for invalid apv type', async () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apv: 'invalid' as any,
      },
    };

    expect(() => ecdhesDeriveEncryptionKey(params)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for invalid enc type', async () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

    const params: DeriveEncryptionKeyParams = {
      alg: 'ECDH-ES',
      enc: 'invalid' as any,
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {},
    };

    expect(() => ecdhesDeriveEncryptionKey(params)).toThrow(JweNotSupported);
  });
});
