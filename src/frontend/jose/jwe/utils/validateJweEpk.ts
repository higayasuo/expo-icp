import { JweInvalid } from '@/jose/errors';
import { Jwk } from '@/jose/types';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { isJweCrv } from './isJweCrv';
import { decodeJweRequiredBase64Url } from '@/jose/utils/decodeBase64Url';

const ERROR_MESSAGE = '"epk" (Ephemeral Public Key) is invalid';

/**
 * Validates the JWE "epk" (Ephemeral Public Key) header parameter.
 * Currently supports EC (Elliptic Curve) and OKP (Octet Key Pair) key types.
 * The following curves are supported:
 * - P-256, P-384, P-521 (for EC keys)
 * - X25519 (for OKP keys)
 *
 * This function ensures that:
 * - The "epk" parameter is present
 * - The "epk" parameter is a plain object
 * - The "epk" parameter has a valid kty (must be 'EC' or 'OKP')
 * - The "epk" parameter has a valid crv (must be 'P-256', 'P-384', 'P-521', or 'X25519')
 * - The "epk" parameter has valid x coordinate in base64url format
 * - For EC keys, the "epk" parameter has valid y coordinate in base64url format
 *
 * @param {unknown} epk - The "epk" parameter value to validate
 * @returns {Jwk} The validated Ephemeral Public Key
 * @throws {JweInvalid} If the "epk" parameter is invalid
 */
export const validateJweEpk = (epk: unknown): Jwk => {
  if (epk == null) {
    console.log('"epk" (Ephemeral Public Key) is missing');
    throw new JweInvalid(ERROR_MESSAGE);
  }

  if (!isPlainObject<Jwk>(epk)) {
    console.log('"epk" (Ephemeral Public Key) is not a plain object');
    throw new JweInvalid(ERROR_MESSAGE);
  }

  if (epk.kty !== 'EC' && epk.kty !== 'OKP') {
    console.log(
      'The kty of "epk" (Ephemeral Public Key) must be "EC" or "OKP"',
    );
    throw new JweInvalid(ERROR_MESSAGE);
  }

  if (!isJweCrv(epk.crv)) {
    console.log(
      'The crv of "epk" (Ephemeral Public Key) must be "P-256", "P-384", "P-521" or "X25519"',
    );
    throw new JweInvalid(ERROR_MESSAGE);
  }

  decodeJweRequiredBase64Url({
    b64u: epk.x,
    label: 'The x of "epk" (Ephemeral Public Key)',
  });

  // Only validate y coordinate for EC keys
  if (epk.kty === 'EC') {
    decodeJweRequiredBase64Url({
      b64u: epk.y,
      label: 'y',
    });
  }

  return epk;
};
