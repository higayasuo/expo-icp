import { describe, it, expect } from 'vitest';
import { parseBase64UrlHeader } from '../parseBase64UrlHeader';
import { JoseInvalid } from '@/jose/errors/errors';
import { encodeBase64Url } from 'u8a-utils';

describe('parseBase64UrlHeader', () => {
  it('should parse valid Jose Header', () => {
    const header = { alg: 'ECDH-ES', enc: 'A256GCM' };
    const b64u = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify(header)),
    );

    const result = parseBase64UrlHeader(b64u, 'Test Header');

    expect(result).toEqual(header);
  });

  it('should throw JoseInvalid for invalid base64url', () => {
    expect(() => parseBase64UrlHeader('invalid', 'Test Header')).toThrow(
      new JoseInvalid('Failed to parse base64url encoded "Test Header"'),
    );
  });

  it('should throw JoseInvalid for invalid JSON', () => {
    const b64u = encodeBase64Url(new TextEncoder().encode('invalid json'));
    expect(() => parseBase64UrlHeader(b64u, 'Test Header')).toThrow(
      new JoseInvalid('Failed to parse base64url encoded "Test Header"'),
    );
  });

  it('should throw JoseInvalid for array JSON', () => {
    const b64u = encodeBase64Url(new TextEncoder().encode('[]'));
    expect(() => parseBase64UrlHeader(b64u, 'Test Header')).toThrow(
      new JoseInvalid('Failed to parse base64url encoded "Test Header"'),
    );
  });

  it('should throw JoseInvalid for null JSON', () => {
    const b64u = encodeBase64Url(new TextEncoder().encode('null'));
    expect(() => parseBase64UrlHeader(b64u, 'Test Header')).toThrow(
      new JoseInvalid('Failed to parse base64url encoded "Test Header"'),
    );
  });

  it('should throw JoseInvalid for undefined input', () => {
    expect(() => parseBase64UrlHeader(undefined, 'Test Header')).toThrow(
      new JoseInvalid('"Test Header" is missing'),
    );
  });

  it('should throw JoseInvalid for null input', () => {
    expect(() => parseBase64UrlHeader(null, 'Test Header')).toThrow(
      new JoseInvalid('"Test Header" is missing'),
    );
  });

  it('should throw JoseInvalid for non-string input', () => {
    expect(() => parseBase64UrlHeader(123, 'Test Header')).toThrow(
      new JoseInvalid('"Test Header" must be a string'),
    );
  });
});
