import { describe, it, expect } from 'vitest';
import { ecdhesManageDecryptKey } from '../ecdhesManageDecryptKey';
import { ecdhesManageEncryptKey } from '../ecdhesManageEncryptKey';
import type { ManageEncryptKeyParams } from '../manageEncryptKey';
import type { ManageDecryptKeyParams } from '../manageDecryptKey';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { createNistCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);

describe('ecdhesManageDecryptKey', () => {
  it('should derive the same CEK as ecdhesManageEncryptKey with apu/apv', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const apu = new TextEncoder().encode('Alice');
    const apv = new TextEncoder().encode('Bob');

    // First, encrypt to get the header parameters
    const encryptParams: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {
        apu,
        apv,
      },
    };

    const encryptResult = ecdhesManageEncryptKey(encryptParams);

    // Then, decrypt using the same parameters
    const decryptParams: ManageDecryptKeyParams = {
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: rawPrivateKey,
      encryptedKey: undefined,
      protectedHeader: {
        ...encryptResult.parameters,
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      },
    };

    const decryptResult = ecdhesManageDecryptKey(decryptParams);

    // Verify the CEKs match
    expect(decryptResult).toEqual(encryptResult.cek);
  });

  it('should derive the same CEK as ecdhesManageEncryptKey without apu/apv', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

    // First, encrypt to get the header parameters
    const encryptParams: ManageEncryptKeyParams = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: rawPublicKey,
      providedParameters: {},
    };

    const encryptResult = ecdhesManageEncryptKey(encryptParams);

    // Then, decrypt using the same parameters
    const decryptParams: ManageDecryptKeyParams = {
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: rawPrivateKey,
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        epk: encryptResult.parameters.epk,
      },
    };

    const decryptResult = ecdhesManageDecryptKey(decryptParams);

    // Verify the CEKs match
    expect(decryptResult).toEqual(encryptResult.cek);
  });

  it('should throw JweInvalid when epk is missing', () => {
    const decryptParams: ManageDecryptKeyParams = {
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: new Uint8Array([1, 2, 3]),
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      },
    };

    expect(() => ecdhesManageDecryptKey(decryptParams)).toThrow(
      'JOSE Header "epk" (Ephemeral Public Key) missing/invalid',
    );
  });
});
