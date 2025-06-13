import { describe, it, expect } from 'vitest';
import { verifyJweHeaders } from '../verifyJweHeaders';
import { JweInvalid } from '@/jose/errors/errors';
import type { JweHeaderParameters } from '../../../types';

describe('verifyJweHeaders', () => {
  describe('overall header combination tests', () => {
    it('should not throw when at least one header is present', () => {
      const validCases: Array<{
        protectedHeader: JweHeaderParameters | undefined;
        sharedUnprotectedHeader: JweHeaderParameters | undefined;
        unprotectedHeader: JweHeaderParameters | undefined;
      }> = [
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: undefined,
          unprotectedHeader: undefined,
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: undefined,
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: undefined,
          unprotectedHeader: { kid: 'key-1' },
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { kid: 'key-1' },
        },
      ];
      validCases.forEach((params) => {
        expect(() => verifyJweHeaders(params)).not.toThrow();
      });
    });

    it('should throw JweInvalid when no headers are present', () => {
      expect(() =>
        verifyJweHeaders({
          protectedHeader: undefined,
          sharedUnprotectedHeader: undefined,
          unprotectedHeader: undefined,
        }),
      ).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when headers have duplicate keys', () => {
      const invalidCases: Array<{
        protectedHeader: JweHeaderParameters | undefined;
        sharedUnprotectedHeader: JweHeaderParameters | undefined;
        unprotectedHeader: JweHeaderParameters | undefined;
      }> = [
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { alg: 'ECDH-ES' },
          unprotectedHeader: undefined,
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: undefined,
          unprotectedHeader: { alg: 'ECDH-ES' },
        },
        {
          protectedHeader: undefined,
          sharedUnprotectedHeader: { alg: 'ECDH-ES' },
          unprotectedHeader: { alg: 'ECDH-ES' },
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { alg: 'ECDH-ES' },
          unprotectedHeader: { alg: 'ECDH-ES' },
        },
        {
          protectedHeader: { alg: 'ECDH-ES', kid: 'key-1' },
          sharedUnprotectedHeader: { kid: 'key-1' },
          unprotectedHeader: undefined,
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { enc: 'A256GCM' },
        },
      ];
      invalidCases.forEach((params) => {
        expect(() => verifyJweHeaders(params)).toThrow(JweInvalid);
      });
    });

    it('should not throw when headers have different keys', () => {
      const validCases: Array<{
        protectedHeader: JweHeaderParameters | undefined;
        sharedUnprotectedHeader: JweHeaderParameters | undefined;
        unprotectedHeader: JweHeaderParameters | undefined;
      }> = [
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: undefined,
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: undefined,
          unprotectedHeader: { enc: 'A256GCM' },
        },
        {
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { kid: 'key-1' },
        },
      ];
      validCases.forEach((params) => {
        expect(() => verifyJweHeaders(params)).not.toThrow();
      });
    });
  });

  describe('protectedHeader only', () => {
    it('should throw JweInvalid if protectedHeader is missing', () => {
      expect(() =>
        verifyJweHeaders({
          protectedHeader: undefined,
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { kid: 'key-1' },
        }),
      ).toThrow(JweInvalid);
    });

    it('should throw JweInvalid if protectedHeader is not a plain object', () => {
      expect(() =>
        verifyJweHeaders({
          protectedHeader: 123 as any,
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { kid: 'key-1' },
        }),
      ).toThrow(JweInvalid);
      expect(() =>
        verifyJweHeaders({
          protectedHeader: null as any,
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { kid: 'key-1' },
        }),
      ).toThrow(JweInvalid);
    });

    it('should throw JweInvalid if protectedHeader is an empty object', () => {
      expect(() =>
        verifyJweHeaders({
          protectedHeader: {},
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: { kid: 'key-1' },
        }),
      ).toThrow(JweInvalid);
    });
  });

  describe('unprotectedHeader only', () => {
    it('should throw JweInvalid if unprotectedHeader is not a plain object', () => {
      expect(() =>
        verifyJweHeaders({
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: { enc: 'A256GCM' },
          unprotectedHeader: 123 as any,
        }),
      ).toThrow(JweInvalid);
    });
  });

  describe('sharedUnprotectedHeader only', () => {
    it('should throw JweInvalid if sharedUnprotectedHeader is not a plain object', () => {
      expect(() =>
        verifyJweHeaders({
          protectedHeader: { alg: 'ECDH-ES' },
          sharedUnprotectedHeader: 123 as any,
          unprotectedHeader: { kid: 'key-1' },
        }),
      ).toThrow(JweInvalid);
    });
  });
});
