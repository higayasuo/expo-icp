import { describe, it, expect } from 'vitest';
import { createP256, createP384, createP521 } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { toB64U } from 'u8a-utils';
import { Share } from 'react-native';

const { getRandomBytes } = webCryptoModule;

// Check which curves are supported by the Web Crypto API implementation
const checkSupportedCurves = async () => {
  const curves = ['P-256', 'P-384', 'P-521'];
  const supported = {
    generateKey: [] as string[],
    importKey: [] as string[],
  };

  for (const curve of curves) {
    try {
      // First generate a valid key pair
      const keyPair = await crypto.subtle.generateKey(
        {
          name: 'ECDH',
          namedCurve: curve,
        },
        true, // extractable
        ['deriveKey', 'deriveBits'],
      );

      supported.generateKey.push(curve);

      // Export the private key as JWK
      const jwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      console.log('exported jwkPrivateKey', jwk);

      // Try to import the exported key
      await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'ECDH', namedCurve: curve },
        false,
        ['deriveKey', 'deriveBits'],
      );
      supported.importKey.push(curve);
    } catch (e) {
      console.log(`Curve ${curve} is not supported:`, e);
    }
  }

  return supported;
};

const secToCryptoKeys = async (
  privateKey: Uint8Array,
  publicKey: Uint8Array,
): Promise<[CryptoKey, CryptoKey]> => {
  const keyLength = privateKey.length;
  const expectedPublicKeyLength = keyLength * 2 + 1;

  if (publicKey.length !== expectedPublicKeyLength) {
    throw new Error(
      `The length of the public key must be ${expectedPublicKeyLength}, but actual ${publicKey.length}`,
    );
  }

  if (publicKey[0] !== 4) {
    throw new Error(
      'Public key must be in uncompressed format (starting with 0x04)',
    );
  }

  // Extract coordinates
  const x = publicKey.slice(1, 1 + keyLength);
  const y = publicKey.slice(1 + keyLength, expectedPublicKeyLength);

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
  return await Promise.all([
    crypto.subtle.importKey(
      'jwk',
      jwkPrivateKey,
      { name: 'ECDH', namedCurve: crv },
      false,
      ['deriveKey', 'deriveBits'],
    ),
    crypto.subtle.importKey(
      'raw',
      publicKey,
      { name: 'ECDH', namedCurve: crv },
      false,
      [],
    ),
  ]);
};

const deriveBits = async (
  priv: CryptoKey,
  pub: CryptoKey,
  bitsLength: number,
): Promise<Uint8Array> =>
  new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: 'ECDH',
        public: pub,
      },
      priv,
      bitsLength,
    ),
  );

/**
 * Compares the shared secret derived from noble-curves-extended's NIST curves
 * with the shared secret derived from the Web Crypto API for the same key pair.
 */
describe('NIST curves shared secret compatibility', () => {
  it('should check supported curves', async () => {
    const supported = await checkSupportedCurves();
    console.log('Supported curves:', supported);
    expect(supported.generateKey).toContain('P-256');
    expect(supported.generateKey).toContain('P-384');
    expect(supported.importKey).toContain('P-256');
    expect(supported.importKey).toContain('P-384');
  });

  it.each([
    ['P-256', createP256],
    ['P-384', createP384],
    ['P-521', createP521],
  ])(
    'should produce the same shared secret as Web Crypto API for %s',
    async (name, createCurve) => {
      try {
        // Generate key pairs using noble-curves
        const curve = createCurve(getRandomBytes);
        const privA = curve.utils.randomPrivateKey();
        const pubA = curve.getPublicKey(privA, false);
        const privB = curve.utils.randomPrivateKey();
        const pubB = curve.getPublicKey(privB, false);

        // noble: derive shared secret
        const nobleSharedSecretA = curve.getSharedSecret(privA, pubB).slice(1);
        console.log('sharedSecretA.length', nobleSharedSecretA.length);
        const nobleSharedSecretB = curve.getSharedSecret(privB, pubA).slice(1);

        // Import keys into Web Crypto API
        const [privAWeb, pubAWeb] = await secToCryptoKeys(privA, pubA);
        const [privBWeb, pubBWeb] = await secToCryptoKeys(privB, pubB);

        // Web Crypto: derive shared secret
        const webSharedSecretA = await deriveBits(
          privAWeb,
          pubBWeb,
          privA.length * 8,
        );

        const webSharedSecretB = await deriveBits(
          privBWeb,
          pubAWeb,
          privB.length * 8,
        );

        expect(nobleSharedSecretA.length).toBe(privA.length);
        // Compare noble and Web Crypto shared secrets
        expect(nobleSharedSecretA).toEqual(webSharedSecretA);
        expect(nobleSharedSecretB).toEqual(webSharedSecretB);
        // Also check that both parties derive the same secret
        expect(nobleSharedSecretA).toEqual(nobleSharedSecretB);
        expect(webSharedSecretA).toEqual(webSharedSecretB);
      } catch (e) {
        console.error(`Error in ${name} test:`, e);
        throw e;
      }
    },
  );
});
