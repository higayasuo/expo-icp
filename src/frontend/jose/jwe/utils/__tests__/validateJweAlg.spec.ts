import { describe, it, expect } from 'vitest';
import { validateJweAlg } from '../validateJweAlg';
import { JweInvalid, JweNotSupported } from '@/jose/errors';
import type { JweAlg } from '../../types';

describe('validateJweAlg', () => {
  it('should return the algorithm when valid', () => {
    const validAlg: JweAlg = 'ECDH-ES';
    expect(validateJweAlg(validAlg)).toBe(validAlg);
  });

  it('should throw JweInvalid when alg is missing', () => {
    expect(() => validateJweAlg(undefined)).toThrow(JweInvalid);
    expect(() => validateJweAlg(null)).toThrow(JweInvalid);
    expect(() => validateJweAlg('')).toThrow(JweInvalid);
  });

  it('should throw JweInvalid when alg is not a string', () => {
    expect(() => validateJweAlg(123)).toThrow(JweInvalid);
    expect(() => validateJweAlg({})).toThrow(JweInvalid);
    expect(() => validateJweAlg([])).toThrow(JweInvalid);
    expect(() => validateJweAlg(true)).toThrow(JweInvalid);
  });

  it('should throw JweNotSupported for unsupported algorithms', () => {
    const unsupportedAlgorithms = [
      'RSA-OAEP', // Different key management algorithm
      'A128GCM', // Content encryption algorithm
      'HS256', // JWS algorithm
      'invalid-alg', // Completely invalid
    ];

    unsupportedAlgorithms.forEach((alg) => {
      expect(() => validateJweAlg(alg)).toThrow(JweNotSupported);
    });
  });
});
