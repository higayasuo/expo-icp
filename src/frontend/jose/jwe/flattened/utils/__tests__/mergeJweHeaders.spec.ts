import { describe, it, expect } from 'vitest';
import { mergeJweHeaders } from '../mergeJweHeaders';
import { JweInvalid, JweNotSupported } from '@/jose/errors/errors';

describe('mergeJweHeaders', () => {
  it('should merge headers with different keys', () => {
    const params = {
      protectedHeader: { alg: 'ECDH-ES' as const },
      sharedUnprotectedHeader: { enc: 'A256GCM' as const },
      unprotectedHeader: { kid: 'key-1' },
    };

    const result = mergeJweHeaders(params);

    expect(result).toEqual({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      kid: 'key-1',
    });
  });

  it('should handle undefined headers', () => {
    const params = {
      protectedHeader: { alg: 'ECDH-ES' as const },
      sharedUnprotectedHeader: undefined,
      unprotectedHeader: undefined,
    };

    const result = mergeJweHeaders(params);

    expect(result).toEqual({
      alg: 'ECDH-ES',
    });
  });

  it('should throw JweInvalid when no headers are present', () => {
    const params = {
      protectedHeader: undefined,
      sharedUnprotectedHeader: undefined,
      unprotectedHeader: undefined,
    };

    expect(() => mergeJweHeaders(params)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid when headers have duplicate keys', () => {
    const params = {
      protectedHeader: { alg: 'ECDH-ES' as const },
      sharedUnprotectedHeader: { alg: 'ECDH-ES' as const },
      unprotectedHeader: undefined,
    };

    expect(() => mergeJweHeaders(params)).toThrow(JweInvalid);
  });

  it('should throw JweNotSupported when zip parameter is present', () => {
    const params = {
      protectedHeader: { alg: 'ECDH-ES' as const },
      sharedUnprotectedHeader: { zip: 'DEF' as const },
      unprotectedHeader: undefined,
    };

    expect(() => mergeJweHeaders(params)).toThrow(JweNotSupported);
  });

  it('should throw JweNotSupported when zip parameter is in protected header', () => {
    const params = {
      protectedHeader: { alg: 'ECDH-ES' as const, zip: 'DEF' as const },
      sharedUnprotectedHeader: undefined,
      unprotectedHeader: undefined,
    };

    expect(() => mergeJweHeaders(params)).toThrow(JweNotSupported);
  });

  it('should throw JweNotSupported when zip parameter is in unprotected header', () => {
    const params = {
      protectedHeader: { alg: 'ECDH-ES' as const },
      sharedUnprotectedHeader: undefined,
      unprotectedHeader: { zip: 'DEF' as const },
    };

    expect(() => mergeJweHeaders(params)).toThrow(JweNotSupported);
  });
});
