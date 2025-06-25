import { describe, it, expect } from 'vitest';
import { validateJweEnc } from '../validateJweEnc';
import { JweInvalid, JweNotSupported } from '@/jose/errors';

describe('validateJweEnc', () => {
  it('should return the encryption algorithm when valid', () => {
    const validAlgorithms = [
      'A128GCM',
      'A192GCM',
      'A256GCM',
      'A128CBC-HS256',
      'A192CBC-HS384',
      'A256CBC-HS512',
    ];

    validAlgorithms.forEach((alg) => {
      expect(validateJweEnc(alg)).toBe(alg);
    });
  });

  it('should throw JweInvalid when enc is missing', () => {
    expect(() => validateJweEnc(undefined)).toThrow(JweInvalid);
    expect(() => validateJweEnc(null)).toThrow(JweInvalid);
    expect(() => validateJweEnc('')).toThrow(JweInvalid);
  });

  it('should throw JweInvalid when enc is not a string', () => {
    expect(() => validateJweEnc(123)).toThrow(JweInvalid);
    expect(() => validateJweEnc({})).toThrow(JweInvalid);
    expect(() => validateJweEnc([])).toThrow(JweInvalid);
    expect(() => validateJweEnc(true)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid when enc is an invalid algorithm', () => {
    const invalidAlgorithms = [
      'A128GCM-256', // Invalid variant
      'A256CBC', // Missing HMAC part
      'AES-GCM', // Wrong format
      'RSA-OAEP', // Wrong algorithm family
    ];

    invalidAlgorithms.forEach((alg) => {
      expect(() => validateJweEnc(alg)).toThrow(JweNotSupported);
    });
  });
});
