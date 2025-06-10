import { describe, it, expect } from 'vitest';
import { parseB64JweHeader } from '../parseB64JweHeader';
import { JweInvalid } from '@/jose/errors';

describe('parseB64JweHeader', () => {
  it('should return undefined when input is undefined', () => {
    const result = parseB64JweHeader(undefined, 'test');
    expect(result).toBeUndefined();
  });

  it('should throw JweInvalid when input is not a string', () => {
    const invalidInputs = [123, true, {}, [], null];

    invalidInputs.forEach((input) => {
      expect(() => parseB64JweHeader(input, 'test')).toThrow(JweInvalid);
      expect(() => parseB64JweHeader(input, 'test')).toThrow(
        'JWE Header "test" must be a string',
      );
    });
  });

  it('should successfully decode valid base64url-encoded strings', () => {
    const testCases = [
      { input: 'SGVsbG8=', expected: new Uint8Array([72, 101, 108, 108, 111]) }, // "Hello" with padding
      { input: 'SGVsbG8', expected: new Uint8Array([72, 101, 108, 108, 111]) }, // "Hello" without padding
      { input: 'dGVzdA==', expected: new Uint8Array([116, 101, 115, 116]) }, // "test" with padding
      { input: 'dGVzdA', expected: new Uint8Array([116, 101, 115, 116]) }, // "test" without padding
      { input: '', expected: new Uint8Array([]) }, // empty string
      {
        input: 'SGVsbG8-',
        expected: new Uint8Array([72, 101, 108, 108, 111, 62]),
      }, // "Hello>" with URL-safe character
      {
        input: 'SGVsbG8_',
        expected: new Uint8Array([72, 101, 108, 108, 111, 63]),
      }, // "Hello?" with URL-safe character
    ];

    testCases.forEach(({ input, expected }) => {
      const result = parseB64JweHeader(input, 'test');
      expect(result).toEqual(expected);
    });
  });

  it('should throw JweInvalid when input is invalid base64url-encoded string', () => {
    const invalidInputs = [
      'SGVsbG8@', // invalid character (@ is not allowed in base64url)
      'dGVzdA=', // invalid padding length (should be 'dGVzdA==' or 'dGVzdA')
      'SGVsbG8==', // invalid padding (multiple = at the end)
    ];

    invalidInputs.forEach((input) => {
      expect(() => parseB64JweHeader(input, 'test')).toThrow(JweInvalid);
      expect(() => parseB64JweHeader(input, 'test')).toThrow(
        'Failed to base64url decode "test"',
      );
    });
  });
});
