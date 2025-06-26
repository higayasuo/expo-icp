import { describe, it, expect } from 'vitest';
import { parseB64 } from '../parseB64';
import { JwsInvalid } from '@/jose/errors/errors';

describe('parseB64', () => {
  describe('when b64 is not critical', () => {
    it('should return true when b64 is not in critical parameters', () => {
      const criticalParamNames = new Set(['alg', 'kid']);
      const b64 = false;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should return true when b64 is undefined and not critical', () => {
      const criticalParamNames = new Set(['alg']);
      const b64 = undefined;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should return true when b64 is null and not critical', () => {
      const criticalParamNames = new Set(['alg']);
      const b64 = null;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should return true when b64 is invalid type and not critical', () => {
      const criticalParamNames = new Set(['alg']);
      const b64 = 'not a boolean';

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });
  });

  describe('when b64 is critical', () => {
    it('should return true when b64 is true and critical', () => {
      const criticalParamNames = new Set(['b64', 'alg']);
      const b64 = true;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should return false when b64 is false and critical', () => {
      const criticalParamNames = new Set(['b64', 'alg']);
      const b64 = false;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(false);
    });

    it('should return true when b64 is undefined and critical (defaults to true)', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = undefined;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should return true when b64 is null and critical (defaults to true)', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = null;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should throw JwsInvalid when b64 is string and critical', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = 'true';

      expect(() => parseB64(b64, criticalParamNames)).toThrow(
        new JwsInvalid(
          'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
        ),
      );
    });

    it('should throw JwsInvalid when b64 is number and critical', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = 1;

      expect(() => parseB64(b64, criticalParamNames)).toThrow(
        new JwsInvalid(
          'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
        ),
      );
    });

    it('should throw JwsInvalid when b64 is object and critical', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = { value: true };

      expect(() => parseB64(b64, criticalParamNames)).toThrow(
        new JwsInvalid(
          'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
        ),
      );
    });

    it('should throw JwsInvalid when b64 is array and critical', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = [true];

      expect(() => parseB64(b64, criticalParamNames)).toThrow(
        new JwsInvalid(
          'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
        ),
      );
    });
  });

  describe('edge cases', () => {
    it('should handle empty critical parameters set', () => {
      const criticalParamNames = new Set<string>();
      const b64 = false;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should handle critical parameters set with only b64', () => {
      const criticalParamNames = new Set(['b64']);
      const b64 = true;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(true);
    });

    it('should handle multiple critical parameters including b64', () => {
      const criticalParamNames = new Set(['b64', 'alg', 'kid', 'crit']);
      const b64 = false;

      const result = parseB64(b64, criticalParamNames);

      expect(result).toBe(false);
    });
  });
});
