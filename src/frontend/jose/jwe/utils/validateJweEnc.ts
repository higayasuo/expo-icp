import { JweInvalid, JweNotSupported } from '@/jose/errors';
import { isEnc } from 'aes-universal';
import { JweEnc } from '../types';

const INVALID_ERROR_MESSAGE = '"enc" (Content Encryption Algorithm) is invalid';
const NOT_SUPPORTED_ERROR_MESSAGE =
  'The specified "enc" (Content Encryption Algorithm) is not supported';

/**
 * Validates the JWE "enc" (Content Encryption Algorithm) header parameter.
 * Currently, the following algorithms are supported:
 * - A128GCM
 * - A192GCM
 * - A256GCM
 * - A128CBC-HS256
 * - A192CBC-HS384
 * - A256CBC-HS512
 *
 * This function ensures that:
 * - The "enc" parameter is present
 * - The "enc" parameter is a string
 * - The "enc" parameter is a valid encryption algorithm
 *
 * @param {unknown} enc - The "enc" parameter value to validate
 * @returns {JweEnc} The validated JWE Content Encryption Algorithm
 * @throws {JweInvalid} If the "enc" parameter is missing or not a string
 * @throws {JweNotSupported} If the "enc" parameter is not supported
 */
export const validateJweEnc = (enc: unknown): JweEnc => {
  if (enc == null) {
    console.log('"enc" (Content Encryption Algorithm) is missing');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (enc === '') {
    console.log('"enc" (Content Encryption Algorithm) is empty');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (typeof enc !== 'string') {
    console.log('"enc" (Content Encryption Algorithm) must be a string');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (!isEnc(enc)) {
    console.log(
      `The specified "enc" (Content Encryption Algorithm) is not supported: ${enc}. Only "A128GCM", "A192GCM", "A256GCM", "A128CBC-HS256", "A192CBC-HS384", and "A256CBC-HS512" are supported.`,
    );
    throw new JweNotSupported(NOT_SUPPORTED_ERROR_MESSAGE);
  }

  return enc;
};
