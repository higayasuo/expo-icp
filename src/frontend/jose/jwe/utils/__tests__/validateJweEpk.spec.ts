import { describe, expect, it } from 'vitest';
import { validateJweEpk } from '../validateJweEpk';
import { JweInvalid } from '@/jose/errors';
import { Jwk } from '@/jose/types';

describe('validateJweEpk', () => {
  const validEcEpk: Jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: 'SGVsbG8',
    y: 'SGVsbG8',
  };

  const validOkpEpk: Jwk = {
    kty: 'OKP',
    crv: 'X25519',
    x: 'SGVsbG8',
  };

  it('should validate a valid EC ephemeral public key', () => {
    const result = validateJweEpk(validEcEpk);
    expect(result).toEqual(validEcEpk);
  });

  it('should validate a valid OKP ephemeral public key', () => {
    const result = validateJweEpk(validOkpEpk);
    expect(result).toEqual(validOkpEpk);
  });

  it('should validate EC keys with different supported curves', () => {
    const curves = ['P-256', 'P-384', 'P-521'] as const;
    curves.forEach((crv) => {
      const epk = { ...validEcEpk, crv };
      const result = validateJweEpk(epk);
      expect(result).toEqual(epk);
    });
  });

  it('should validate OKP keys with X25519 curve', () => {
    const epk = { ...validOkpEpk, crv: 'X25519' };
    const result = validateJweEpk(epk);
    expect(result).toEqual(epk);
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

  it('should throw when kty is not EC or OKP', () => {
    const invalidEpks = [
      { ...validEcEpk, kty: 'RSA' },
      { ...validEcEpk, kty: 'oct' },
      { ...validEcEpk, kty: 'invalid' },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should throw when crv is invalid', () => {
    const invalidEpks = [
      { ...validEcEpk, crv: 'P-128' },
      { ...validEcEpk, crv: 'secp256k1' },
      { ...validEcEpk, crv: 'invalid' },
      { ...validEcEpk, crv: undefined },
      { ...validOkpEpk, crv: 'Ed25519' },
      { ...validOkpEpk, crv: 'invalid' },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should throw when x is invalid', () => {
    const invalidEpks = [
      { ...validEcEpk, x: undefined },
      { ...validEcEpk, x: 'invalid!' },
      { ...validEcEpk, x: 123 },
      { ...validOkpEpk, x: undefined },
      { ...validOkpEpk, x: 'invalid!' },
      { ...validOkpEpk, x: 123 },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should throw when y is missing for EC keys', () => {
    const invalidEpks = [
      { ...validEcEpk, y: undefined },
      { ...validEcEpk, y: 'invalid!' },
      { ...validEcEpk, y: 123 },
    ];

    invalidEpks.forEach((epk) => {
      expect(() => validateJweEpk(epk)).toThrow(JweInvalid);
    });
  });

  it('should not require y for OKP keys', () => {
    const okpEpkWithoutY = { ...validOkpEpk };
    delete (okpEpkWithoutY as any).y;
    const result = validateJweEpk(okpEpkWithoutY);
    expect(result).toEqual(okpEpkWithoutY);
  });
});
