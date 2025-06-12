import { describe, it, expect } from 'vitest';
import { validateJwkPublicKeyAgainstCurve } from '../validateJwkPublicKeyAgainstCurve';
import { createNistCurve } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { JoseInvalid } from '@/jose/errors';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);

describe('validateJwkPublicKeyAgainstCurve', () => {
  it('should return raw public key for valid JWK public key', () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

    const result = validateJwkPublicKeyAgainstCurve(jwkPublicKey, curve);

    expect(result).toBeInstanceOf(Uint8Array);
    expect(result).toEqual(rawPublicKey);
  });

  it('should throw JweInvalid for invalid kty', () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

    expect(() =>
      validateJwkPublicKeyAgainstCurve(
        {
          ...jwkPublicKey,
          kty: 'RSA',
        },
        curve,
      ),
    ).toThrow(JoseInvalid);
  });

  it('should throw JweInvalid for invalid crv', () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

    expect(() =>
      validateJwkPublicKeyAgainstCurve(
        {
          ...jwkPublicKey,
          crv: 'P-384',
        },
        curve,
      ),
    ).toThrow(JoseInvalid);
  });

  it('should throw JweInvalid for invalid x coordinate', () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

    expect(() =>
      validateJwkPublicKeyAgainstCurve(
        {
          ...jwkPublicKey,
          x: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        },
        curve,
      ),
    ).toThrow(JoseInvalid);
  });

  it('should throw JweInvalid for invalid y coordinate', () => {
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

    expect(() =>
      validateJwkPublicKeyAgainstCurve(
        {
          ...jwkPublicKey,
          y: 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
        },
        curve,
      ),
    ).toThrow(JoseInvalid);
  });
});
