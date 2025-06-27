import { describe, it, expect } from 'vitest';
import { isJwsAlg } from '../isJwsAlg';
import { JWS_ALGS } from '../../constants';

describe('isJwsAlg', () => {
  describe('valid JWS algorithms', () => {
    it.each(JWS_ALGS)('should return true for valid algorithm: %s', (alg) => {
      expect(isJwsAlg(alg)).toBe(true);
    });
  });

  describe('invalid inputs', () => {
    it('should return false for invalid algorithm strings', () => {
      expect(isJwsAlg('RS256')).toBe(false);
      expect(isJwsAlg('HS256')).toBe(false);
      expect(isJwsAlg('PS256')).toBe(false);
      expect(isJwsAlg('invalid-alg')).toBe(false);
      expect(isJwsAlg('')).toBe(false);
    });

    it('should return false for non-string values', () => {
      expect(isJwsAlg(null)).toBe(false);
      expect(isJwsAlg(undefined)).toBe(false);
      expect(isJwsAlg(123)).toBe(false);
      expect(isJwsAlg({})).toBe(false);
      expect(isJwsAlg([])).toBe(false);
      expect(isJwsAlg(true)).toBe(false);
      expect(isJwsAlg(false)).toBe(false);
    });

    it('should return false for case variations', () => {
      expect(isJwsAlg('es256')).toBe(false);
      expect(isJwsAlg('Es256')).toBe(false);
      expect(isJwsAlg('ES256 ')).toBe(false);
      expect(isJwsAlg(' ES256')).toBe(false);
    });

    it('should return false for partial matches', () => {
      expect(isJwsAlg('ES')).toBe(false);
      expect(isJwsAlg('256')).toBe(false);
      expect(isJwsAlg('ES25')).toBe(false);
    });
  });

  describe('type guard behavior', () => {
    it('should narrow the type when used in conditional statements', () => {
      const testAlg = 'ES256' as unknown;

      if (isJwsAlg(testAlg)) {
        // TypeScript should know testAlg is JwsAlg here
        expect(typeof testAlg).toBe('string');
        expect(testAlg).toBe('ES256');
      } else {
        expect.fail('Should not reach here');
      }
    });

    it('should work with unknown type', () => {
      const unknownValue: unknown = 'ES384';

      if (isJwsAlg(unknownValue)) {
        // TypeScript should narrow unknownValue to JwsAlg
        expect(unknownValue).toBe('ES384');
      } else {
        expect.fail('Should not reach here');
      }
    });
  });
});
