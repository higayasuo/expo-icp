import { describe, it, expect } from 'vitest';
import { validateJweAlg } from '../validateJweAlg';
import { JweInvalid, JweNotSupported } from '@/jose/errors';
import type { JweAlg } from '../../types';

describe('validateJweAlg', () => {
  it('should return the algorithm when valid', () => {
    const validAlg: JweAlg = 'ECDH-ES';
    expect(validateJweAlg(validAlg)).toBe(validAlg);
  });

  it('should throw JweInvalid when alg is null or undefined', () => {
    expect(() => validateJweAlg(undefined)).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
    expect(() => validateJweAlg(null)).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
  });

  it('should throw JweInvalid when alg is empty string', () => {
    expect(() => validateJweAlg('')).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
  });

  it('should throw JweInvalid when alg is not a string', () => {
    expect(() => validateJweAlg(123)).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
    expect(() => validateJweAlg({})).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
    expect(() => validateJweAlg([])).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
    expect(() => validateJweAlg(true)).toThrow(
      new JweInvalid('"alg" (Key Management Algorithm) is invalid'),
    );
  });

  it('should throw JweNotSupported for unsupported algorithms', () => {
    const unsupportedAlgorithms = [
      'RSA-OAEP', // Different key management algorithm
      'A128GCM', // Content encryption algorithm
      'HS256', // JWS algorithm
      'invalid-alg', // Completely invalid
    ];

    unsupportedAlgorithms.forEach((alg) => {
      expect(() => validateJweAlg(alg)).toThrow(
        new JweNotSupported(
          'The specified "alg" (Key Management Algorithm) is not supported',
        ),
      );
    });
  });
});
