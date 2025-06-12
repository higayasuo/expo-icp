import { describe, it, expect } from 'vitest';
import { buildBase64UrlJweHeader } from '../buildBase64UrlJweHeader';
import { decodeBase64Url } from 'u8a-utils';

const decoder = new TextDecoder();

describe('buildBase64UrlJweHeader', () => {
  it('should return empty string when header is undefined', () => {
    const result = buildBase64UrlJweHeader(undefined);
    expect(result).toBe('');
  });

  it('should return empty string when header is empty object', () => {
    const result = buildBase64UrlJweHeader({});
    const decoded = JSON.parse(decoder.decode(decodeBase64Url(result)));
    expect(decoded).toEqual({});
  });

  it('should encode header object to base64url', () => {
    const header = {
      alg: 'ECDH-ES',
      enc: 'A256GCM',
    };
    const result = buildBase64UrlJweHeader(header);
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
    const result = buildBase64UrlJweHeader(header);
    const decoded = JSON.parse(decoder.decode(decodeBase64Url(result)));
    expect(decoded).toEqual(header);
  });
});
