import { describe, it, expect } from 'vitest';
import { mergeJwsHeaders } from '../mergeJwsHeader';
import { JwsInvalid } from '@/jose/errors/errors';
import { JwsHeaderParameters } from '@/jose/jws/types';

describe('mergeJwsHeaders', () => {
  describe('header merging', () => {
    it('should merge headers with different keys', () => {
      const params = {
        protectedHeader: { alg: 'ES256' as const },
        unprotectedHeader: { kid: 'key-1' },
      };

      const result = mergeJwsHeaders(params);

      expect(result).toEqual({
        alg: 'ES256',
        kid: 'key-1',
      });
    });

    it('should handle undefined unprotected header', () => {
      const params = {
        protectedHeader: { alg: 'ES256' as const },
        unprotectedHeader: undefined,
      };

      const result = mergeJwsHeaders(params);

      expect(result).toEqual({
        alg: 'ES256',
      });
    });

    it('should merge complex headers with various parameters', () => {
      const protectedHeader: JwsHeaderParameters = {
        alg: 'ES256',
        crit: ['b64'],
        b64: false,
      };
      const unprotectedHeader: JwsHeaderParameters = {
        kid: 'test-key',
        x5t: 'test-thumbprint',
        cty: 'application/json',
      };

      const result = mergeJwsHeaders({
        protectedHeader,
        unprotectedHeader,
      });

      expect(result).toEqual({
        alg: 'ES256',
        crit: ['b64'],
        b64: false,
        kid: 'test-key',
        x5t: 'test-thumbprint',
        cty: 'application/json',
      });
    });
  });

  describe('validation errors', () => {
    it('should throw JwsInvalid when protected header is missing', () => {
      const params = {
        protectedHeader: undefined,
        unprotectedHeader: undefined,
      };

      expect(() => mergeJwsHeaders(params)).toThrow(
        new JwsInvalid('JWS Protected Header is missing'),
      );
    });

    it('should throw JwsInvalid when protected header is not a plain object', () => {
      const params = {
        protectedHeader: 'not an object' as any,
        unprotectedHeader: undefined,
      };

      expect(() => mergeJwsHeaders(params)).toThrow(
        new JwsInvalid('JWS Protected Header is not a plain object'),
      );
    });

    it('should throw JwsInvalid when protected header is empty', () => {
      const params = {
        protectedHeader: {},
        unprotectedHeader: undefined,
      };

      expect(() => mergeJwsHeaders(params)).toThrow(
        new JwsInvalid('JWS Protected Header is empty'),
      );
    });

    it('should throw JwsInvalid when unprotected header is not a plain object', () => {
      const params = {
        protectedHeader: { alg: 'ES256' },
        unprotectedHeader: 'not an object' as any,
      };

      expect(() => mergeJwsHeaders(params)).toThrow(
        new JwsInvalid('JWS Unprotected Header is not a plain object'),
      );
    });

    it('should throw JwsInvalid when headers have overlapping keys', () => {
      const params = {
        protectedHeader: { alg: 'ES256', kid: 'protected-key' },
        unprotectedHeader: { kid: 'unprotected-key' },
      };

      expect(() => mergeJwsHeaders(params)).toThrow(
        new JwsInvalid(
          'JWS Protected and JWS Unprotected Header Parameter names must be disjoint',
        ),
      );
    });
  });

  describe('edge cases', () => {
    it('should handle empty unprotected header object', () => {
      const params = {
        protectedHeader: { alg: 'ES256' as const },
        unprotectedHeader: {},
      };

      const result = mergeJwsHeaders(params);

      expect(result).toEqual({
        alg: 'ES256',
      });
    });

    it('should handle nested objects in headers', () => {
      const params = {
        protectedHeader: { alg: 'ES256' as const },
        unprotectedHeader: {
          kid: 'key-1',
          custom: { nested: 'value' },
        },
      };

      const result = mergeJwsHeaders(params);

      expect(result).toEqual({
        alg: 'ES256',
        kid: 'key-1',
        custom: { nested: 'value' },
      });
    });

    it('should handle boolean values in headers', () => {
      const params = {
        protectedHeader: { alg: 'ES256' as const, b64: false },
        unprotectedHeader: {
          kid: 'key-1',
          crit: ['b64'],
        },
      };

      const result = mergeJwsHeaders(params);

      expect(result).toEqual({
        alg: 'ES256',
        b64: false,
        kid: 'key-1',
        crit: ['b64'],
      });
    });
  });
});
