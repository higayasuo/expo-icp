import { describe, it, expect } from 'vitest';
import { verifyJweHeaders } from '../verifyJweHeaders';
import { JweInvalid } from '@/jose/errors/errors';
import type { JweHeaderParameters } from '../../../types';

describe('verifyJweHeaders', () => {
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
        protectedHeader: undefined,
        sharedUnprotectedHeader: { alg: 'ECDH-ES' },
        unprotectedHeader: undefined,
      },
      {
        protectedHeader: undefined,
        sharedUnprotectedHeader: undefined,
        unprotectedHeader: { alg: 'ECDH-ES' },
      },
      {
        protectedHeader: { alg: 'ECDH-ES' },
        sharedUnprotectedHeader: { enc: 'A256GCM' },
        unprotectedHeader: undefined,
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
        protectedHeader: undefined,
        sharedUnprotectedHeader: { alg: 'ECDH-ES' },
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
