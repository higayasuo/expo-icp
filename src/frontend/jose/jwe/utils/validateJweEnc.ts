import { JweInvalid } from '@/jose/errors';
import { isEnc } from 'aes-universal';
import { JweEnc } from '../types';

/**
 * Validates the JWE "enc" (Content Encryption Algorithm) header parameter.
 *
 * This function ensures that:
 * - The "enc" parameter is present
 * - The "enc" parameter is a string
 * - The "enc" parameter is a valid encryption algorithm
 *
 * @param {unknown} enc - The "enc" parameter value to validate
 * @returns {JweEnc} The validated JWE Content Encryption Algorithm
 * @throws {JweInvalid} If the "enc" parameter is missing, not a string, or invalid
 */
export const validateJweEnc = (enc: unknown): JweEnc => {
  if (!enc) {
    throw new JweInvalid(
      'JWE Header "enc" (Content Encryption Algorithm) missing',
    );
  }
  if (typeof enc !== 'string') {
    throw new JweInvalid(
      'JWE Header "enc" (Content Encryption Algorithm) must be a string',
    );
  }
  if (!isEnc(enc)) {
    throw new JweInvalid(
      'JWE Header "enc" (Content Encryption Algorithm) must be A128GCM, A192GCM, A256GCM, A128CBC-HS256, A192CBC-HS384, or A256CBC-HS512',
    );
  }

  return enc;
};
