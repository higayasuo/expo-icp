import { JweCrv } from '../types';

/**
 * Type guard to check if a value is a valid JWE curve name.
 *
 * This function checks if the input value is one of the supported NIST curves:
 * - P-256
 * - P-384
 * - P-521
 *
 * @param crv - The value to check
 * @returns {boolean} True if the value is a valid JWE curve name, false otherwise
 * @example
 * // Returns true
 * isJweCrv('P-256');
 * @example
 * // Returns false
 * isJweCrv('invalid-curve');
 */
export const isJweCrv = (crv: unknown): crv is JweCrv => {
  return (
    crv === 'P-256' || crv === 'P-384' || crv === 'P-521' || crv === 'X25519'
  );
};
