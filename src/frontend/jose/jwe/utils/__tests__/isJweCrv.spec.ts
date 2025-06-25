import { describe, expect, it } from 'vitest';
import { isJweCrv } from '../isJweCrv';
import { JweCrv } from '../../types';

describe('isJweCrv', () => {
  it('should return true for valid JWE curve names', () => {
    const validCurves: JweCrv[] = ['P-256', 'P-384', 'P-521', 'X25519'];
    validCurves.forEach((crv) => {
      expect(isJweCrv(crv)).toBe(true);
    });
  });

  it('should return false for invalid curve names', () => {
    const invalidCurves = [
      'P-128',
      'P-512',
      'invalid',
      'secp256k1',
      'ed25519',
      '',
      null,
      undefined,
      123,
      true,
      {},
      [],
    ];

    invalidCurves.forEach((crv) => {
      expect(isJweCrv(crv)).toBe(false);
    });
  });

  it('should narrow the type when used in a type guard context', () => {
    const value: unknown = 'P-256';
    if (isJweCrv(value)) {
      // TypeScript should know that value is JweCrv here
      const crv: JweCrv = value; // This should not cause a type error
      expect(crv).toBe('P-256');
    }
  });
});
