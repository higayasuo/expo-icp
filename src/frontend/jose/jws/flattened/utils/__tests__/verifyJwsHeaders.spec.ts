import { describe, it, expect } from 'vitest';
import { verifyJwsHeaders } from '../verifyJwsHeaders';
import { JwsInvalid } from '@/jose/errors/errors';
import { JwsHeaderParameters } from '@/jose/jws/types';

describe('verifyJwsHeaders', () => {
  describe('protected header validation', () => {
    it('should throw JwsInvalid when protected header is undefined', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: undefined,
          unprotectedHeader: undefined,
        }),
      ).toThrow(new JwsInvalid('JWS Protected Header is missing'));
    });

    it('should throw JwsInvalid when protected header is null', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: null as any,
          unprotectedHeader: undefined,
        }),
      ).toThrow(new JwsInvalid('JWS Protected Header is missing'));
    });

    it('should throw JwsInvalid when protected header is not a plain object', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: 'not an object' as any,
          unprotectedHeader: undefined,
        }),
      ).toThrow(new JwsInvalid('JWS Protected Header is not a plain object'));
    });

    it('should throw JwsInvalid when protected header is an array', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: [] as any,
          unprotectedHeader: undefined,
        }),
      ).toThrow(new JwsInvalid('JWS Protected Header is not a plain object'));
    });

    it('should throw JwsInvalid when protected header is empty', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: {},
          unprotectedHeader: undefined,
        }),
      ).toThrow(new JwsInvalid('JWS Protected Header is empty'));
    });
  });

  describe('unprotected header validation', () => {
    it('should not throw when unprotected header is undefined', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: undefined,
        }),
      ).not.toThrow();
    });

    it('should not throw when unprotected header is a valid plain object', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: { kid: 'test-key' },
        }),
      ).not.toThrow();
    });

    it('should throw JwsInvalid when unprotected header is not a plain object', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: 'not an object' as any,
        }),
      ).toThrow(new JwsInvalid('JWS Unprotected Header is not a plain object'));
    });

    it('should throw JwsInvalid when unprotected header is an array', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: [] as any,
        }),
      ).toThrow(new JwsInvalid('JWS Unprotected Header is not a plain object'));
    });
  });

  describe('disjoint key validation', () => {
    it('should not throw when headers have different keys', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: { kid: 'test-key' },
        }),
      ).not.toThrow();
    });

    it('should not throw when unprotected header is undefined', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: undefined,
        }),
      ).not.toThrow();
    });

    it('should throw JwsInvalid when headers have overlapping keys', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256', kid: 'protected-key' },
          unprotectedHeader: { kid: 'unprotected-key' },
        }),
      ).toThrow(
        new JwsInvalid(
          'JWS Protected and JWS Unprotected Header Parameter names must be disjoint',
        ),
      );
    });
  });

  describe('valid cases', () => {
    it('should not throw with valid protected header only', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: undefined,
        }),
      ).not.toThrow();
    });

    it('should not throw with valid protected and unprotected headers', () => {
      expect(() =>
        verifyJwsHeaders({
          protectedHeader: { alg: 'ES256' },
          unprotectedHeader: { kid: 'test-key', cty: 'application/json' },
        }),
      ).not.toThrow();
    });

    it('should not throw with complex valid headers', () => {
      const protectedHeader: JwsHeaderParameters = {
        alg: 'ES256',
        crit: ['b64'],
        b64: false,
      };
      const unprotectedHeader: JwsHeaderParameters = {
        kid: 'test-key',
        x5t: 'test-thumbprint',
      };

      expect(() =>
        verifyJwsHeaders({
          protectedHeader,
          unprotectedHeader,
        }),
      ).not.toThrow();
    });
  });
});
