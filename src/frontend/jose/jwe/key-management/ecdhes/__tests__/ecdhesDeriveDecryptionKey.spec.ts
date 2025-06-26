import { describe, expect, it } from 'vitest';
import { ecdhesDeriveDecryptionKey } from '../ecdhesDriveDecryptionKey';
import { ecdhesDeriveEncryptionKey } from '../ecdhesDeriveEncryptKey';
import { createEcdhCurve } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { JoseInvalid, JweInvalid, JweNotSupported } from '@/jose/errors';
import { encodeBase64Url } from 'u8a-utils';

const { getRandomBytes } = webCryptoModule;

describe('ecdhesDeriveDecryptionKey', () => {
  const curve = createEcdhCurve('P-256', getRandomBytes);
  const privateKey = curve.randomPrivateKey();
  const publicKey = curve.getPublicKey(privateKey);

  it('should derive the same CEK as ecdhesDeriveEncryptionKey when apu and apv are provided', async () => {
    const encryptResult = await ecdhesDeriveEncryptionKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: {
        apu: new TextEncoder().encode('Alice'),
        apv: new TextEncoder().encode('Bob'),
      },
    });

    const decryptResult = ecdhesDeriveDecryptionKey({
      enc: 'A256GCM',
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: privateKey,
      encryptedKey: undefined,
      protectedHeader: encryptResult.parameters,
    });

    expect(decryptResult).toEqual(encryptResult.cek);
  });

  it('should derive the same CEK as ecdhesDeriveEncryptionKey when apu and apv are not provided', async () => {
    const encryptResult = await ecdhesDeriveEncryptionKey({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      curve,
      yourPublicKey: publicKey,
      providedParameters: undefined,
    });

    const decryptResult = ecdhesDeriveDecryptionKey({
      enc: 'A256GCM',
      alg: 'ECDH-ES',
      curve,
      myPrivateKey: privateKey,
      encryptedKey: undefined,
      protectedHeader: encryptResult.parameters,
    });

    expect(decryptResult).toEqual(encryptResult.cek);
  });

  describe('epk validation', () => {
    it('should throw JweInvalid when epk is missing', () => {
      expect(() =>
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {},
        }),
      ).toThrow(new JweInvalid('"epk" (Ephemeral Public Key) is invalid'));
    });

    it('should throw JweInvalid when epk.kty is not EC', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        curve,
        yourPublicKey: publicKey,
        providedParameters: undefined,
      });

      expect(() =>
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            epk: {
              kty: 'RSA',
              crv: encryptResult.parameters.epk!.crv,
              x: encryptResult.parameters.epk!.x,
              y: encryptResult.parameters.epk!.y,
            },
          },
        }),
      ).toThrow(new JweInvalid('"epk" (Ephemeral Public Key) is invalid'));
    });

    it('should throw Error when epk.crv does not match curve.curveName', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        curve,
        yourPublicKey: publicKey,
        providedParameters: undefined,
      });

      expect(() =>
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            epk: {
              kty: 'EC',
              crv: 'P-384',
              x: encryptResult.parameters.epk!.x,
              y: encryptResult.parameters.epk!.y,
            },
          },
        }),
      ).toThrow('Failed to convert JWK to raw public key');
    });

    it('should throw Error when epk.x is outside the elliptic curve range', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        curve,
        yourPublicKey: publicKey,
        providedParameters: undefined,
      });

      expect(() =>
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            epk: {
              kty: 'EC',
              crv: encryptResult.parameters.epk!.crv,
              x: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
              y: encryptResult.parameters.epk!.y,
            },
          },
        }),
      ).toThrow('Failed to convert JWK to raw public key');
    });
  });

  describe('apu validation', () => {
    it('should throw JweInvalid when apu is not base64url encoded', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
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
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            apu: 'invalid base64url!@#',
          },
        }),
      ).toThrow(new JweInvalid('"apu (Agreement PartyUInfo)" is invalid'));
    });

    it('should throw JweInvalid when apu exceeds 32 bytes', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
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
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            apu: encodeBase64Url(new TextEncoder().encode('A'.repeat(33))), // 33 bytes in base64url
          },
        }),
      ).toThrow(
        new JweInvalid(
          '"apu (Agreement PartyUInfo)" must be less than or equal to 32 bytes',
        ),
      );
    });
  });

  describe('apv validation', () => {
    it('should throw JweInvalid when apv is not base64url encoded', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
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
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            apv: 'invalid base64url!@#',
          },
        }),
      ).toThrow(new JweInvalid('"apv (Agreement PartyVInfo)" is invalid'));
    });

    it('should throw JweInvalid when apv exceeds 32 bytes', async () => {
      const encryptResult = await ecdhesDeriveEncryptionKey({
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
        ecdhesDeriveDecryptionKey({
          enc: 'A256GCM',
          alg: 'ECDH-ES',
          curve,
          myPrivateKey: privateKey,
          encryptedKey: undefined,
          protectedHeader: {
            ...encryptResult.parameters,
            apv: encodeBase64Url(new TextEncoder().encode('A'.repeat(33))), // 33 bytes in base64url
          },
        }),
      ).toThrow(
        new JweInvalid(
          '"apv (Agreement PartyVInfo)" must be less than or equal to 32 bytes',
        ),
      );
    });
  });
});
