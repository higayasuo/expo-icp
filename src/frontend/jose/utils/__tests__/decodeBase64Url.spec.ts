import { describe, expect, it } from 'vitest';
import {
  decodeOptionalBase64Url,
  decodeRequiredBase64Url,
} from '../decodeBase64Url';
import { JoseInvalid } from '@/jose/errors';

describe('decodeBase64Url', () => {
  describe('decodeOptionalBase64Url', () => {
    it('should decode a valid base64url string', () => {
      const result = decodeOptionalBase64Url({
        b64u: 'SGVsbG8',
        label: 'test',
      });
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should return undefined for undefined input', () => {
      const result = decodeOptionalBase64Url({
        b64u: undefined,
        label: 'test',
      });
      expect(result).toBeUndefined();
    });

    it('should throw JoseInvalid when input is not a string', () => {
      expect(() =>
        decodeOptionalBase64Url({
          b64u: 123,
          label: 'test',
        }),
      ).toThrow(new JoseInvalid('"test" must be a string'));
    });

    it('should throw JoseInvalid when input is invalid base64url', () => {
      expect(() =>
        decodeOptionalBase64Url({
          b64u: 'invalid!',
          label: 'test',
        }),
      ).toThrow(new JoseInvalid('Failed to base64url decode "test"'));
    });
  });

  describe('decodeRequiredBase64Url', () => {
    it('should decode a valid base64url string', () => {
      const result = decodeRequiredBase64Url({
        b64u: 'SGVsbG8',
        label: 'test',
      });
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should throw JoseInvalid when input is undefined', () => {
      expect(() =>
        decodeRequiredBase64Url({
          b64u: undefined,
          label: 'test',
        }),
      ).toThrow(new JoseInvalid('"test" is missing'));
    });

    it('should throw JoseInvalid when input is not a string', () => {
      expect(() =>
        decodeRequiredBase64Url({
          b64u: 123,
          label: 'test',
        }),
      ).toThrow(new JoseInvalid('"test" must be a string'));
    });

    it('should throw JoseInvalid when input is invalid base64url', () => {
      expect(() =>
        decodeRequiredBase64Url({
          b64u: 'invalid!',
          label: 'test',
        }),
      ).toThrow(new JoseInvalid('Failed to base64url decode "test"'));
    });
  });
});
