import { JweInvalid, JweNotSupported } from '@/jose/errors';
import { JweAlg } from '../types';
import { isJweAlg } from './isJweAlg';

const INVALID_ERROR_MESSAGE = '"alg" (Key Management Algorithm) is invalid';
const NOT_SUPPORTED_ERROR_MESSAGE =
  'The specified "alg" (Key Management Algorithm) is not supported';

/**
 * Validates the JWE "alg" (Key Management Algorithm) header parameter.
 * Currently, only ECDH-ES is supported.
 *
 * This function ensures that:
 * - The "alg" parameter is present
 * - The "alg" parameter is a string
 * - The "alg" parameter is a valid key management algorithm
 *
 * @param {unknown} alg - The "alg" parameter value to validate
 * @returns {JweAlg} The validated key management algorithm
 * @throws {JweInvalid} If the "alg" parameter is missing or not a string
 * @throws {JweNotSupported} If the "alg" parameter is not supported
 */
export const validateJweAlg = (alg: unknown): JweAlg => {
  if (alg == null) {
    console.log('"alg" (Key Management Algorithm) is missing');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (alg === '') {
    console.log('"alg" (Key Management Algorithm) is empty');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (typeof alg !== 'string') {
    console.log('"alg" (Key Management Algorithm) must be a string');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (!isJweAlg(alg)) {
    console.log(
      `The specified "alg" (Key Management Algorithm) is not supported: ${alg}. Only "ECDH-ES" is supported.`,
    );
    throw new JweNotSupported(NOT_SUPPORTED_ERROR_MESSAGE);
  }

  return alg;
};
