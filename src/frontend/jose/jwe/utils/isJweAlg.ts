import { JweAlg } from '../types';

/**
 * Type guard to check if a value is a valid JWE algorithm
 * Currently, only ECDH-ES is supported.
 * @param alg - The value to check
 * @returns {boolean} True if the value is a valid JWE algorithm, false otherwise
 * @example
 * // Returns true
 * isJweAlg('ECDH-ES');
 * @example
 * // Returns false
 * isJweAlg('invalid-alg');
 */
export const isJweAlg = (alg: unknown): alg is JweAlg => {
  return alg === 'ECDH-ES';
};
