import { Jwk } from '@/jose/types';
import { JoseInvalid } from '@/jose/errors';
import { NistCurve } from 'noble-curves-extended';

const ERROR_MESSAGE = 'Invalid JWK public key';

/**
 * Validates a JWK public key against a specified elliptic curve and converts it to a raw public key.
 *
 * @param {Jwk} jwkPublicKey - The JWK public key to validate and convert.
 * @param {NistCurve} curve - The elliptic curve to validate the JWK public key against.
 * @returns {Uint8Array} The raw public key derived from the JWK.
 * @throws {JweInvalid} If the JWK public key is invalid for the specified curve.
 */
export const validateJwkPublicKeyAgainstCurve = (
  jwkPublicKey: Jwk,
  curve: NistCurve,
): Uint8Array => {
  if (jwkPublicKey.kty !== 'EC') {
    console.error(`${ERROR_MESSAGE}: kty "${jwkPublicKey.kty}" is not "EC"`);
    throw new JoseInvalid(ERROR_MESSAGE);
  }

  if (jwkPublicKey.crv !== curve.curveName) {
    console.error(
      `${ERROR_MESSAGE}: crv "${jwkPublicKey.crv}" is not "${curve.curveName}"`,
    );
    throw new JoseInvalid(ERROR_MESSAGE);
  }

  try {
    return curve.toRawPublicKey(jwkPublicKey);
  } catch (error) {
    console.error(error);
    throw new JoseInvalid('Invalid JWK public key');
  }
};
