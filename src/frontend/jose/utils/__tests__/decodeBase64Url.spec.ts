import { describe, expect, it } from 'vitest';
import {
  decodeJweOptionalBase64Url,
  decodeJweRequiredBase64Url,
  decodeJwsOptionalBase64Url,
  decodeJwsRequiredBase64Url,
} from '../decodeBase64Url';
import { JweInvalid, JwsInvalid } from '@/jose/errors';

describe('decodeBase64Url', () => {
  const validB64U = 'SGVsbG8gV29ybGQ'; // "Hello World" in base64url
  const invalidB64U = 'invalid!@#';

  describe('decodeJweOptionalBase64Url', () => {
    it('should decode a valid base64url string', () => {
      const result = decodeJweOptionalBase64Url({
        b64u: 'SGVsbG8',
        label: 'test',
      });
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should return undefined for undefined input', () => {
      const result = decodeJweOptionalBase64Url({
        b64u: undefined,
        label: 'test',
      });
      expect(result).toBeUndefined();
    });

    it('should throw JweInvalid when input is not a string', () => {
      expect(() =>
        decodeJweOptionalBase64Url({
          b64u: 123,
          label: 'test',
        }),
      ).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when input is invalid base64url', () => {
      expect(() =>
        decodeJweOptionalBase64Url({
          b64u: 'invalid!',
          label: 'test',
        }),
      ).toThrow(JweInvalid);
    });
  });

  describe('decodeJweRequiredBase64Url', () => {
    it('should decode a valid base64url string', () => {
      const result = decodeJweRequiredBase64Url({
        b64u: 'SGVsbG8',
        label: 'test',
      });
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should throw JweInvalid when input is undefined', () => {
      expect(() =>
        decodeJweRequiredBase64Url({
          b64u: undefined,
          label: 'test',
        }),
      ).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when input is not a string', () => {
      expect(() =>
        decodeJweRequiredBase64Url({
          b64u: 123,
          label: 'test',
        }),
      ).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when input is invalid base64url', () => {
      expect(() =>
        decodeJweRequiredBase64Url({
          b64u: 'invalid!',
          label: 'test',
        }),
      ).toThrow(JweInvalid);
    });
  });

  describe('decodeJwsOptionalBase64Url', () => {
    it('should decode a valid base64url string', () => {
      const result = decodeJwsOptionalBase64Url({
        b64u: 'SGVsbG8',
        label: 'test',
      });
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should return undefined for undefined input', () => {
      const result = decodeJwsOptionalBase64Url({
        b64u: undefined,
        label: 'test',
      });
      expect(result).toBeUndefined();
    });

    it('should throw JwsInvalid when input is not a string', () => {
      expect(() =>
        decodeJwsOptionalBase64Url({
          b64u: 123,
          label: 'test',
        }),
      ).toThrow(JwsInvalid);
    });

    it('should throw JwsInvalid when input is invalid base64url', () => {
      expect(() =>
        decodeJwsOptionalBase64Url({
          b64u: 'invalid!',
          label: 'test',
        }),
      ).toThrow(JwsInvalid);
    });
  });

  describe('decodeJwsRequiredBase64Url', () => {
    it('should decode a valid base64url string', () => {
      const result = decodeJwsRequiredBase64Url({
        b64u: 'SGVsbG8',
        label: 'test',
      });
      expect(result).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should throw JwsInvalid when input is undefined', () => {
      expect(() =>
        decodeJwsRequiredBase64Url({
          b64u: undefined,
          label: 'test',
        }),
      ).toThrow(JwsInvalid);
    });

    it('should throw JwsInvalid when input is not a string', () => {
      expect(() =>
        decodeJwsRequiredBase64Url({
          b64u: 123,
          label: 'test',
        }),
      ).toThrow(JwsInvalid);
    });

    it('should throw JwsInvalid when input is invalid base64url', () => {
      expect(() =>
        decodeJwsRequiredBase64Url({
          b64u: 'invalid!',
          label: 'test',
        }),
      ).toThrow(JwsInvalid);
    });
  });
});
