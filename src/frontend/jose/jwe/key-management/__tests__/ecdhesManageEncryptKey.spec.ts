import { describe, it, expect } from 'vitest';
import { ecdhesManageEncryptKey } from '../ecdhesManageEncryptKey';
import type { ManageEncryptKeyParams } from '../manageEncryptKey';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';
import { toB64U } from 'u8a-utils';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('ecdhesManageEncryptKey', () => {
  it('should return correct CEK, undefined encryptedKey, and header parameters with apu/apv', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const apu = new TextEncoder().encode('Alice');
    const apv = new TextEncoder().encode('Bob');

    const params: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apu,
        apv,
      },
    };

    const result = ecdhesManageEncryptKey(params);

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
      apu: toB64U(apu),
      apv: toB64U(apv),
    });
    expect(curve.toRawPublicKey(result.parameters.epk!).length).toEqual(65);
  });

  it('should omit apu/apv if not provided', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

    const params: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {},
    };

    const result = ecdhesManageEncryptKey(params);

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

    const params1: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey1,
      providedParameters: {},
    };

    const params2: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey2,
      providedParameters: {},
    };

    const result1 = ecdhesManageEncryptKey(params1);
    const result2 = ecdhesManageEncryptKey(params2);

    // Verify CEKs are different
    expect(result1.cek).not.toEqual(result2.cek);
  });
});
