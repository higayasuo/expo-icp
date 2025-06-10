import { describe, expect, it } from 'vitest';
import { ecdhesManageDecryptKey } from '../ecdhesManageDecryptKey';
import { ecdhesManageEncryptKey } from '../ecdhesManageEncryptKey';
import { createNistCurve } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { JweInvalid } from '@/jose/errors';

const { getRandomBytes } = webCryptoModule;

describe('ecdhesManageDecryptKey', () => {
  const curve = createNistCurve('P-256', getRandomBytes);
  const privateKey = curve.utils.randomPrivateKey();
  const publicKey = curve.getPublicKey(privateKey, false);

  it('should derive the same CEK as ecdhesManageEncryptKey when apu and apv are provided', async () => {
    const encryptResult = await ecdhesManageEncryptKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: {
        apu: new TextEncoder().encode('Alice'),
        apv: new TextEncoder().encode('Bob'),
      },
    });

    const decryptResult = ecdhesManageDecryptKey({
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: privateKey,
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        ...encryptResult.parameters,
      },
    });

    expect(decryptResult).toEqual(encryptResult.cek);
  });

  it('should derive the same CEK as ecdhesManageEncryptKey when apu and apv are not provided', async () => {
    const encryptResult = await ecdhesManageEncryptKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: undefined,
    });

    const decryptResult = ecdhesManageDecryptKey({
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: privateKey,
      encryptedKey: undefined,
      protectedHeader: {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        ...encryptResult.parameters,
      },
    });

    expect(decryptResult).toEqual(encryptResult.cek);
  });

  it('should throw JweInvalid when epk is missing', () => {
    expect(() =>
      ecdhesManageDecryptKey({
        alg: 'ECDH-ES',
        curve,
        myPrivateKey: privateKey,
        encryptedKey: undefined,
        protectedHeader: {
          alg: 'ECDH-ES',
          enc: 'A256GCM',
        },
      }),
    ).toThrow(
      new JweInvalid(
        'JOSE Header "epk" (Ephemeral Public Key) missing/invalid',
      ),
    );
  });

  it('should throw JweInvalid when apu is not base64url encoded', async () => {
    const encryptResult = await ecdhesManageEncryptKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: {
        apu: new TextEncoder().encode('Alice'),
        apv: new TextEncoder().encode('Bob'),
      },
    });

    expect(() =>
      ecdhesManageDecryptKey({
        alg: 'ECDH-ES',
        curve,
        myPrivateKey: privateKey,
        encryptedKey: undefined,
        protectedHeader: {
          alg: 'ECDH-ES',
          enc: 'A256GCM',
          ...encryptResult.parameters,
          apu: 'invalid base64url!@#',
        },
      }),
    ).toThrow(
      new JweInvalid(
        'Failed to base64url decode "apu (Agreement PartyUInfo)": InvalidCharacterError: Invalid character',
      ),
    );
  });

  it('should throw JweInvalid when apv is not base64url encoded', async () => {
    const encryptResult = await ecdhesManageEncryptKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: {
        apu: new TextEncoder().encode('Alice'),
        apv: new TextEncoder().encode('Bob'),
      },
    });

    expect(() =>
      ecdhesManageDecryptKey({
        alg: 'ECDH-ES',
        curve,
        myPrivateKey: privateKey,
        encryptedKey: undefined,
        protectedHeader: {
          alg: 'ECDH-ES',
          enc: 'A256GCM',
          ...encryptResult.parameters,
          apv: 'invalid base64url!@#',
        },
      }),
    ).toThrow(
      new JweInvalid(
        'Failed to base64url decode "apv (Agreement PartyVInfo)": InvalidCharacterError: Invalid character',
      ),
    );
  });

  it('should throw JweInvalid when enc is missing', async () => {
    const encryptResult = await ecdhesManageEncryptKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: undefined,
    });

    expect(() =>
      ecdhesManageDecryptKey({
        alg: 'ECDH-ES',
        curve,
        myPrivateKey: privateKey,
        encryptedKey: undefined,
        protectedHeader: {
          alg: 'ECDH-ES',
          ...encryptResult.parameters,
          enc: undefined,
        },
      }),
    ).toThrow(
      new JweInvalid('JWE Header "enc" (Content Encryption Algorithm) missing'),
    );
  });

  it('should throw JweInvalid when enc is invalid', async () => {
    const encryptResult = await ecdhesManageEncryptKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: undefined,
    });

    expect(() =>
      ecdhesManageDecryptKey({
        alg: 'ECDH-ES',
        curve,
        myPrivateKey: privateKey,
        encryptedKey: undefined,
        protectedHeader: {
          alg: 'ECDH-ES',
          ...encryptResult.parameters,
          enc: 'INVALID-ENC' as any,
        },
      }),
    ).toThrow(
      new JweInvalid(
        'JWE Header "enc" (Content Encryption Algorithm) must be A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, or A256CBC-HS512',
      ),
    );
  });
});
