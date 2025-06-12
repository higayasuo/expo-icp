import { JweInvalid } from '@/jose/errors';
import { Jwk } from '@/jose/types';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { isJweCrv } from './isJweCrv';
import { decodeJweRequiredBase64Url } from '@/jose/utils/decodeBase64Url';

const ERROR_MESSAGE = '"epk" (Ephemeral Public Key) is invalid';

/**
 * Validates the JWE "epk" (Ephemeral Public Key) header parameter.
 * Currently, only EC (Elliptic Curve) is supported for the kty.
 * The following curves are supported:
 * - P-256
 * - P-384
 * - P-521
 *
 * This function ensures that:
 * - The "epk" parameter is present
 * - The "epk" parameter is a plain object
 * - The "epk" parameter has a valid kty (must be 'EC')
 * - The "epk" parameter has a valid crv (must be 'P-256', 'P-384', or 'P-521')
 * - The "epk" parameter has valid x and y coordinates in base64url format
 *
 * @param {unknown} epk - The "epk" parameter value to validate
 * @returns {Jwk} The validated Ephemeral Public Key
 * @throws {JweInvalid} If the "epk" parameter is invalid
 */
export const validateJweEpk = (epk: unknown): Jwk => {
  if (epk === undefined) {
    console.error('"epk" (Ephemeral Public Key) is missing');
    throw new JweInvalid(ERROR_MESSAGE);
  }

  if (!isPlainObject<Jwk>(epk)) {
    console.error('"epk" (Ephemeral Public Key) is not a plain object');
    throw new JweInvalid(ERROR_MESSAGE);
  }

  if (epk.kty !== 'EC') {
    console.error('The kty of "epk" (Ephemeral Public Key) must be "EC"');
    throw new JweInvalid(ERROR_MESSAGE);
  }

  if (!isJweCrv(epk.crv)) {
    console.error(
      'The crv of "epk" (Ephemeral Public Key) must be "P-256", "P-384", or "P-521"',
    );
    throw new JweInvalid(ERROR_MESSAGE);
  }

  decodeJweRequiredBase64Url({
    b64u: epk.x,
    label: 'The x of "epk" (Ephemeral Public Key)',
  });

  decodeJweRequiredBase64Url({
    b64u: epk.y,
    label: 'y',
  });

  return epk;
};
