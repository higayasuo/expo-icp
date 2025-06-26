import { describe, it, expect } from 'vitest';
import { parseJweProtected } from '../parseJweProtected';
import { JweInvalid } from '@/jose/errors/errors';
import { encodeBase64Url } from 'u8a-utils';

describe('parseJweProtected', () => {
  it('should parse valid JWE Protected Header', () => {
    const header = { alg: 'ECDH-ES', enc: 'A256GCM' };
    const b64u = encodeBase64Url(
      new TextEncoder().encode(JSON.stringify(header)),
    );

    const result = parseJweProtected(b64u);

    expect(result).toEqual(header);
  });

  it('should throw JweInvalid for invalid base64url', () => {
    expect(() => parseJweProtected('invalid')).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for invalid JSON', () => {
    const b64u = encodeBase64Url(new TextEncoder().encode('invalid json'));
    expect(() => parseJweProtected(b64u)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for array JSON', () => {
    const b64u = encodeBase64Url(new TextEncoder().encode('[]'));
    expect(() => parseJweProtected(b64u)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for null JSON', () => {
    const b64u = encodeBase64Url(new TextEncoder().encode('null'));
    expect(() => parseJweProtected(b64u)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for undefined input', () => {
    expect(() => parseJweProtected(undefined)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for null input', () => {
    expect(() => parseJweProtected(null)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for non-string input', () => {
    expect(() => parseJweProtected(123)).toThrow(JweInvalid);
  });
});
