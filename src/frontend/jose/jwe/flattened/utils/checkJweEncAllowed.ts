import { JweInvalid } from '@/jose/errors';
import { validateStringArrayAsSet } from '@/jose/utils/validateStringArrayAsSet';

/**
 * Checks if a JWE Content Encryption Algorithm is allowed based on provided allowed algorithms.
 *
 * This function validates whether a given algorithm is permitted by:
 * 1. Converting the allowed algorithms into a Set of strings
 * 2. Checking if the algorithm exists in the allowed set
 *
 * @param {string} enc - The algorithm to check
 * @param {unknown} contentEncryptionAlgorithms - The allowed algorithms (can be undefined, array, or other type)
 * @throws {JweInvalid} - If the algorithm is not allowed
 */
export const checkJweEncAllowed = (
  enc: string,
  contentEncryptionAlgorithms: unknown,
) => {
  const allowedAlgorithms = validateStringArrayAsSet(
    contentEncryptionAlgorithms,
    'contentEncryptionAlgorithms',
  );

  if (allowedAlgorithms && !allowedAlgorithms.has(enc)) {
    console.error(
      'The specified "enc" (Content Encryption Algorithm) is not allowed: %s, allowedAlgorithms: %s',
      enc,
      Array.from(allowedAlgorithms || []).join(', '),
    );
    throw new JweInvalid(
      'The specified "enc" (Content Encryption Algorithm) is not allowed',
    );
  }
};
