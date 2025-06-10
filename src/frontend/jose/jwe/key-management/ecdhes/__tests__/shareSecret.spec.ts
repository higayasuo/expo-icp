import { describe, it, expect } from 'vitest';
import { createP256, createP384, createP521 } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { toB64U } from 'u8a-utils';
import { CurveFn } from '@noble/curves/abstract/weierstrass';

const { getRandomBytes } = webCryptoModule;

const secToPrivateCryptoKeys = async (
  privateKey: Uint8Array,
  curve: CurveFn,
): Promise<CryptoKey> => {
  const keyLength = privateKey.length;
  const publicKey = curve.getPublicKey(privateKey, false);

  // Extract coordinates
  const x = publicKey.slice(1, 1 + keyLength);
  const y = publicKey.slice(1 + keyLength);

  // Map key length to correct curve name
  const crv = (() => {
    switch (keyLength) {
      case 32:
        return 'P-256';
      case 48:
        return 'P-384';
      case 66:
        return 'P-521';
      default:
        throw new Error(`Unsupported key length: ${keyLength}`);
    }
  })();

  // Create JWK for private key
  const jwkPrivateKey = {
    kty: 'EC',
    crv,
    d: toB64U(privateKey),
    x: toB64U(x),
    y: toB64U(y),
  };

  // Import keys
  return crypto.subtle.importKey(
    'jwk',
    jwkPrivateKey,
    { name: 'ECDH', namedCurve: crv },
    false,
    ['deriveKey', 'deriveBits'],
  );
};

const secToPublicCryptoKey = async (
  publicKey: Uint8Array,
): Promise<CryptoKey> => {
  const keyLength = publicKey.length;
  const crv = (() => {
    switch (keyLength) {
      case 33:
      case 65:
        return 'P-256';
      case 49:
      case 97:
        return 'P-384';
      case 67:
      case 133:
        return 'P-521';
      default:
        throw new Error(`Unsupported key length: ${keyLength}`);
    }
  })();

  return crypto.subtle.importKey(
    'raw',
    publicKey,
    { name: 'ECDH', namedCurve: crv },
    false,
    [],
  );
};

const deriveBits = async (
  priv: CryptoKey,
  pub: CryptoKey,
  bitLength: number,
): Promise<Uint8Array> =>
  new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: pub,
      },
      priv,
      bitLength,
    ),
  );

describe('createNobleShareSecret', () => {
  describe('shared secret calculation', () => {
    it.each([
      ['P-256', createP256, 256],
      ['P-384', createP384, 384],
      ['P-521', createP521, 528],
    ])(
      'should calculate shared secret for %s',
      async (name, createCurve, bitLength) => {
        const curve = createCurve(getRandomBytes);

        // Generate key pairs
        const privateKeyA = curve.utils.randomPrivateKey();
        const publicKeyA = curve.getPublicKey(privateKeyA, false);
        const privateKeyB = curve.utils.randomPrivateKey();
        const publicKeyB = curve.getPublicKey(privateKeyB, false);

        const privateKeyAWeb = await secToPrivateCryptoKeys(privateKeyA, curve);
        const publicKeyAWeb = await secToPublicCryptoKey(publicKeyA);
        const privateKeyBWeb = await secToPrivateCryptoKeys(privateKeyB, curve);
        const publicKeyBWeb = await secToPublicCryptoKey(publicKeyB);

        // Calculate shared secrets
        const sharedSecretA = curve
          .getSharedSecret(privateKeyA, publicKeyB, true)
          .slice(1);
        const sharedSecretB = curve
          .getSharedSecret(privateKeyB, publicKeyA, true)
          .slice(1);

        const sharedSecretAWeb = await deriveBits(
          privateKeyAWeb,
          publicKeyBWeb,
          bitLength,
        );
        const sharedSecretBWeb = await deriveBits(
          privateKeyBWeb,
          publicKeyAWeb,
          bitLength,
        );

        // Verify both parties derive the same secret
        expect(sharedSecretA).toEqual(sharedSecretB);
        expect(sharedSecretAWeb).toEqual(sharedSecretA);
        expect(sharedSecretBWeb).toEqual(sharedSecretB);

        // Verify the length of the shared secret
        const expectedLength = (() => {
          switch (name) {
            case 'P-256':
              return 32;
            case 'P-384':
              return 48;
            case 'P-521':
              return 66;
            default:
              throw new Error(`Unsupported curve: ${name}`);
          }
        })();
        expect(sharedSecretA.length).toBe(expectedLength);
      },
    );
  });
});
