import { describe, expect, it } from 'vitest';
import { validateJweEpk } from '../validateJweEpk';
import { JweInvalid } from '@/jose/errors';
import { Jwk } from '@/jose/types';

describe('validateJweEpk', () => {
  const validEpk: Jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'SGVsbG8',
    y: 'SGVsbG8',
  };

  it('should validate a valid ephemeral public key', () => {
    const result = validateJweEpk(validEpk);
    expect(result).toEqual(validEpk);
  });

  it('should throw when epk is undefined', () => {
    expect(() => validateJweEpk(undefined)).toThrow(JweInvalid);
  });

  it('should throw when epk is not a plain object', () => {
    const invalidEpks = [null, 'string', 123, true, [], new Date(), () => {}];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should throw when kty is not EC', () => {
    const invalidEpk = {
      ...validEpk,
      kty: 'RSA',
    };

    expect(() => validateJweEpk(invalidEpk)).toThrow(JweInvalid);
  });

  it('should throw when crv is invalid', () => {
    const invalidEpks = [
      { ...validEpk, crv: 'P-128' },
      { ...validEpk, crv: 'secp256k1' },
      { ...validEpk, crv: 'invalid' },
      { ...validEpk, crv: undefined },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should throw when x is invalid', () => {
    const invalidEpks = [
      { ...validEpk, x: undefined },
      { ...validEpk, x: 'invalid!' },
      { ...validEpk, x: 123 },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should throw when y is invalid', () => {
    const invalidEpks = [
      { ...validEpk, y: undefined },
      { ...validEpk, y: 'invalid!' },
      { ...validEpk, y: 123 },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });
});
