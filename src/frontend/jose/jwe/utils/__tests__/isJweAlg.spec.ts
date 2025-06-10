import { describe, it, expect } from 'vitest';
import { isJweAlg } from '../isJweAlg';
import type { JweAlg } from '../../types';

describe('isJweAlg', () => {
  it('should return true for valid JWE algorithms', () => {
    const validAlg: JweAlg = 'ECDH-ES';
    expect(isJweAlg(validAlg)).toBe(true);
  });

  it('should return false for invalid JWE algorithms', () => {
    const invalidAlgorithms = [
      'RSA-OAEP', // Different key management algorithm
      'A128GCM', // Content encryption algorithm
      'HS256', // JWS algorithm
      'invalid-alg', // Completely invalid
      '', // Empty string
      null, // null
      undefined, // undefined
      123, // number
      {}, // object
      [], // array
      true, // boolean
    ];

    invalidAlgorithms.forEach((alg) => {
      expect(isJweAlg(alg)).toBe(false);
    });
  });

  it('should narrow the type when used in a type guard context', () => {
    const value: unknown = 'ECDH-ES';

    if (isJweAlg(value)) {
      // TypeScript should know that value is JweAlg here
      const alg: JweAlg = value; // This should not cause a type error
      expect(alg).toBe('ECDH-ES');
    }
  });
});
