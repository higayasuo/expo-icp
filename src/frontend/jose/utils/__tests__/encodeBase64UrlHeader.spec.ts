import { describe, it, expect } from 'vitest';
import { encodeBase64UrlHeader } from '../encodeBase64UrlHeader';
import { decodeBase64Url } from 'u8a-utils';

const decoder = new TextDecoder();

describe('encodeBase64UrlHeader', () => {
  it('should return empty string when header is undefined', () => {
    const result = encodeBase64UrlHeader(undefined);
    expect(result).toBe('');
  });

  it('should return empty string when header is empty object', () => {
    const result = encodeBase64UrlHeader({});
    const decoded = JSON.parse(decoder.decode(decodeBase64Url(result)));
    expect(decoded).toEqual({});
  });

  it('should encode header object to base64url', () => {
    const header = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
    };
    const result = encodeBase64UrlHeader(header);
    const decoded = JSON.parse(decoder.decode(decodeBase64Url(result)));
    expect(decoded).toEqual(header);
  });

  it('should handle header with nested objects', () => {
    const header = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      epk: {
        kty: 'EC',
        crv: 'P-256',
        x: 'test-x',
        y: 'test-y',
      },
    };
    const result = encodeBase64UrlHeader(header);
    const decoded = JSON.parse(decoder.decode(decodeBase64Url(result)));
    expect(decoded).toEqual(header);
  });
});
