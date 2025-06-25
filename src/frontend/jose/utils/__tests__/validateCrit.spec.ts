import { describe, it, expect } from 'vitest';
import { validateCrit } from '../validateCrit';
import { JoseNotSupported, JweInvalid, JwsInvalid } from '../../errors';
import type { ValidateCritHeader } from '../validateCrit';

describe('validateCrit', () => {
  const recognizedDefault = {
    'default-param': true,
    'another-param': true,
  };

  const recognizedOption = {
    'optional-param': true,
    'unprotected-param': false,
  };

  describe('with JweInvalid', () => {
    it('should throw if crit exists in unprotected but not in protected', () => {
      const joseHeader: ValidateCritHeader = { crit: ['default-param'] };
      const protectedHeader: ValidateCritHeader = {};

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) Header Parameter MUST be integrity protected',
      );
    });

    it('should throw if crit is not an array', () => {
      const joseHeader: ValidateCritHeader = { crit: ['default-param'] };
      const protectedHeader = {
        crit: 'not-an-array',
      } as unknown as ValidateCritHeader;

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
      );
    });

    it('should throw if crit contains empty strings', () => {
      const joseHeader: ValidateCritHeader = {};
      const protectedHeader: ValidateCritHeader = { crit: [''] };

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
      );
    });

    it('should throw if critical parameter is missing in unprotected header', () => {
      const joseHeader: ValidateCritHeader = {};
      const protectedHeader: ValidateCritHeader = { crit: ['default-param'] };

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) header parameter "default-param" is missing in the JOSE header',
      );
    });

    it('should throw if critical parameter is missing in protected header', () => {
      const joseHeader: ValidateCritHeader = { 'default-param': 'value' };
      const protectedHeader: ValidateCritHeader = { crit: ['default-param'] };

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) header parameter "default-param" MUST be integrity protected',
      );
    });
  });

  describe('crit parameter validation', () => {
    it('should throw JweInvalid when options.crit contains non-existent parameter', () => {
      const joseHeader: ValidateCritHeader = { 'unknown-param': 'value' };
      const protectedHeader: ValidateCritHeader = {
        crit: ['unknown-param'],
        'unknown-param': 'value',
      };

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) header parameter "unknown-param" is not recognized',
      );
    });

    it('should work correctly when protectedHeader.crit is properly configured', () => {
      const joseHeader: ValidateCritHeader = { 'default-param': 'value' };
      const protectedHeader: ValidateCritHeader = {
        crit: ['default-param'],
        'default-param': 'value',
      };

      const result = validateCrit({
        Err: JweInvalid,
        recognizedDefault,
        recognizedOption: undefined,
        protectedHeader,
        joseHeader,
      });
      expect(result).toEqual(new Set(['default-param']));
    });
  });

  describe('with JwsInvalid', () => {
    it('should throw if crit exists in unprotected but not in protected', () => {
      const joseHeader: ValidateCritHeader = { crit: ['default-param'] };
      const protectedHeader: ValidateCritHeader = {};

      expect(() =>
        validateCrit({
          Err: JwsInvalid,
          recognizedDefault,
          recognizedOption: undefined,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) Header Parameter MUST be integrity protected',
      );
    });
  });

  describe('with optional recognized parameters', () => {
    it('should accept recognized optional parameters that require integrity protection', () => {
      const joseHeader: ValidateCritHeader = { 'optional-param': 'value' };
      const protectedHeader: ValidateCritHeader = {
        crit: ['optional-param'],
        'optional-param': 'value',
      };

      const result = validateCrit({
        Err: JweInvalid,
        recognizedDefault,
        recognizedOption,
        protectedHeader,
        joseHeader,
      });

      expect(result).toEqual(new Set(['optional-param']));
    });

    it('should accept recognized optional parameters that do not require integrity protection', () => {
      const joseHeader: ValidateCritHeader = { 'unprotected-param': 'value' };
      const protectedHeader: ValidateCritHeader = {
        crit: ['unprotected-param'],
      };

      const result = validateCrit({
        Err: JweInvalid,
        recognizedDefault,
        recognizedOption,
        protectedHeader,
        joseHeader,
      });

      expect(result).toEqual(new Set(['unprotected-param']));
    });

    it('should throw for unrecognized parameters', () => {
      const joseHeader: ValidateCritHeader = { 'unknown-param': 'value' };
      const protectedHeader: ValidateCritHeader = {
        crit: ['unknown-param'],
        'unknown-param': 'value',
      };

      expect(() =>
        validateCrit({
          Err: JweInvalid,
          recognizedDefault,
          recognizedOption,
          protectedHeader,
          joseHeader,
        }),
      ).toThrow(
        '"crit" (Critical) header parameter "unknown-param" is not recognized',
      );
    });
  });

  describe('valid cases', () => {
    it('should return empty set when no crit is present', () => {
      const joseHeader: ValidateCritHeader = {};
      const protectedHeader: ValidateCritHeader = {};

      const result = validateCrit({
        Err: JweInvalid,
        recognizedDefault,
        recognizedOption: undefined,
        protectedHeader,
        joseHeader,
      });
      expect(result).toEqual(new Set());
    });

    it('should handle multiple critical parameters', () => {
      const joseHeader: ValidateCritHeader = {
        'default-param': 'value1',
        'another-param': 'value2',
      };
      const protectedHeader: ValidateCritHeader = {
        crit: ['default-param', 'another-param'],
        'default-param': 'value1',
        'another-param': 'value2',
      };

      const result = validateCrit({
        Err: JweInvalid,
        recognizedDefault,
        recognizedOption: undefined,
        protectedHeader,
        joseHeader,
      });
      expect(result).toEqual(new Set(['default-param', 'another-param']));
    });
  });
});
