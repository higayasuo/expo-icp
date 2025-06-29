import { describe, expect, it } from 'vitest';
import { validateJwsAlg } from '../validateJwsAlg';
import { JwsInvalid, JwsNotSupported } from '@/jose/errors';

describe('validateJwsAlg', () => {
  describe('valid algorithms', () => {
    it('should validate ES256 algorithm', () => {
      const result = validateJwsAlg('ES256', 'ES256');
      expect(result).toBe('ES256');
    });

    it('should validate ES384 algorithm', () => {
      const result = validateJwsAlg('ES384', 'ES384');
      expect(result).toBe('ES384');
    });

    it('should validate ES512 algorithm', () => {
      const result = validateJwsAlg('ES512', 'ES512');
      expect(result).toBe('ES512');
    });

    it('should validate ES256K algorithm', () => {
      const result = validateJwsAlg('ES256K', 'ES256K');
      expect(result).toBe('ES256K');
    });

    it('should validate EdDSA algorithm', () => {
      const result = validateJwsAlg('EdDSA', 'EdDSA');
      expect(result).toBe('EdDSA');
    });
  });

  describe('invalid inputs', () => {
    it('should throw JwsInvalid when alg is null or undefined', () => {
      expect(() => validateJwsAlg(undefined, 'ES256')).toThrow(
        new JwsInvalid('"alg" (Algorithm) is missing'),
      );
      expect(() => validateJwsAlg(null, 'ES256')).toThrow(
        new JwsInvalid('"alg" (Algorithm) is missing'),
      );
    });

    it('should throw JwsInvalid when alg is not a string', () => {
      const invalidAlgs = [123, true, false, [], {}, new Date(), () => {}];

      invalidAlgs.forEach((alg) => {
        expect(() => validateJwsAlg(alg, 'ES256')).toThrow(
          new JwsInvalid('"alg" (Algorithm) must be a string'),
        );
      });
    });

    it('should throw JwsNotSupported when alg is not supported', () => {
      const unsupportedAlgs = [
        'HS256',
        'HS384',
        'HS512',
        'RS256',
        'RS384',
        'RS512',
        'PS256',
        'PS384',
        'PS512',
        'invalid-alg',
        'ES128',
        'ES192',
      ];

      unsupportedAlgs.forEach((alg) => {
        expect(() => validateJwsAlg(alg, 'ES256')).toThrow(
          new JwsNotSupported(
            'The specified "alg" (Algorithm) is not supported',
          ),
        );
      });
    });

    it('should throw JwsInvalid when alg is empty string', () => {
      expect(() => validateJwsAlg('', 'ES256')).toThrow(
        new JwsInvalid('"alg" (Algorithm) is empty'),
      );
    });

    it('should throw JwsInvalid when alg does not match expected value', () => {
      expect(() => validateJwsAlg('ES384', 'ES256')).toThrow(
        new JwsInvalid('"alg" (Algorithm) does not match JWK parameters'),
      );
      expect(() => validateJwsAlg('ES256', 'ES384')).toThrow(
        new JwsInvalid('"alg" (Algorithm) does not match JWK parameters'),
      );
    });
  });
});
