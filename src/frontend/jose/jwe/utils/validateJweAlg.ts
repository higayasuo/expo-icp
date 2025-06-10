import { JweInvalid } from '@/jose/errors';
import { JweAlg } from '../types';
import { isJweAlg } from './isJweAlg';

/**
 * Validates the JWE "alg" (Key Management Algorithm) header parameter.
 *
 * This function ensures that:
 * - The "alg" parameter is present
 * - The "alg" parameter is a string
 * - The "alg" parameter is a valid key management algorithm
 *
 * @param {unknown} alg - The "alg" parameter value to validate
 * @returns {Enc} The validated encryption algorithm
 * @throws {JweInvalid} If the "enc" parameter is missing, not a string, or invalid
 */
export const validateJweAlg = (alg: unknown): JweAlg => {
  if (!alg) {
    throw new JweInvalid('JWE Header "alg" (Key Management Algorithm) missing');
  }
  if (typeof alg !== 'string') {
    throw new JweInvalid(
      'JWE Header "alg" (Key Management Algorithm) must be a string',
    );
  }
  if (!isJweAlg(alg)) {
    throw new JweInvalid(
      'JWE Header "alg" (Key Management Algorithm) must be ECDH-ES',
    );
  }

  return alg;
};
