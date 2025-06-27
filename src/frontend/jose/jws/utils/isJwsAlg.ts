import { JwsAlg } from '../types';
import { JWS_ALGS } from '../constants';

/**
 * Type guard to check if a value is a valid JWS algorithm.
 * It verifies if the provided algorithm is one of the supported JWS algorithms.
 * @param alg - The value to check
 * @returns {boolean} True if the value is a valid JWS algorithm, false otherwise
 * @example
 * // Returns true
 * isJwsAlg('ES256');
 * @example
 * // Returns false
 * isJwsAlg('invalid-alg');
 */
export const isJwsAlg = (alg: unknown): alg is JwsAlg => {
  return JWS_ALGS.includes(alg as JwsAlg);
};
