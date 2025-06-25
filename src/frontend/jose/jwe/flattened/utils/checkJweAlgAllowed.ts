import { JweInvalid } from '@/jose/errors';
import { validateStringArrayAsSet } from '@/jose/utils/validateStringArrayAsSet';

/**
 * Checks if a JWE Key Management Algorithm is allowed based on provided allowed algorithms.
 *
 * This function validates whether a given algorithm is permitted by:
 * 1. Converting the allowed algorithms into a Set of strings
 * 2. Checking if the algorithm exists in the allowed set
 * 3. Special handling for PBES2 algorithms which are only allowed if explicitly permitted
 *
 * @param {string} alg - The algorithm to check
 * @param {unknown} keyManagementAlgorithms - The allowed algorithms (can be undefined, array, or other type)
 * @throws {JweInvalid} - If the algorithm is not allowed
 */
export const checkJweAlgAllowed = (
  alg: string,
  keyManagementAlgorithms: unknown,
) => {
  const allowedAlgorithms = validateStringArrayAsSet(
    keyManagementAlgorithms,
    'keyManagementAlgorithms',
  );

  if (
    (allowedAlgorithms && !allowedAlgorithms.has(alg)) ||
    (!allowedAlgorithms && alg.startsWith('PBES2'))
  ) {
    console.error(
      'The specified "alg" (Key Management Algorithm) is not allowed: %s, allowedAlgorithms: %s',
      alg,
      Array.from(allowedAlgorithms || []).join(', '),
    );
    throw new JweInvalid(
      'The specified "alg" (Key Management Algorithm) is not allowed',
    );
  }
};
