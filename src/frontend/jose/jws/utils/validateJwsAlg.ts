import { JwsInvalid, JwsNotSupported } from '@/jose/errors';
import { JwsAlg } from '@/jose/jws/types';
import { isJwsAlg } from './isJwsAlg';

/**
 * Validates the JWS "alg" (Algorithm) header parameter.
 * Currently supports the following algorithms:
 * - ES256
 * - ES384
 * - ES512
 * - ES256K
 * - EdDSA
 *
 * This function ensures that:
 * - The "alg" parameter is present
 * - The "alg" parameter is a string
 * - The "alg" parameter is a valid algorithm
 *
 * @param {unknown} alg - The "alg" parameter value to validate
 * @param {string} expectedAlg - The expected algorithm based on JWK parameters
 * @returns {JwsAlg} The validated algorithm
 * @throws {JwsInvalid} If the "alg" parameter is missing or not a string
 * @throws {JwsNotSupported} If the "alg" parameter is not supported
 */
export const validateJwsAlg = (alg: unknown, expectedAlg: string): JwsAlg => {
  if (alg == null) {
    throw new JwsInvalid('"alg" (Algorithm) is missing');
  }

  if (alg === '') {
    throw new JwsInvalid('"alg" (Algorithm) is empty');
  }

  if (typeof alg !== 'string') {
    throw new JwsInvalid('"alg" (Algorithm) must be a string');
  }

  if (!isJwsAlg(alg)) {
    console.log(
      `The specified "alg" (Algorithm) is not supported: ${alg}. Only "ES256", "ES384", "ES512", "ES256K", and "EdDSA" are supported.`,
    );
    throw new JwsNotSupported(
      'The specified "alg" (Algorithm) is not supported',
    );
  }

  if (alg !== expectedAlg) {
    console.log(
      `"alg" (Algorithm) mismatch: got "${alg}", expected "${expectedAlg}" based on JWK parameters.`,
    );
    throw new JwsInvalid(`"alg" (Algorithm) does not match JWK parameters`);
  }

  return alg;
};
