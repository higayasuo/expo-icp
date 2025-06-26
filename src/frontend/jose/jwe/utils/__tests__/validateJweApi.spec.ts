import { describe, expect, it } from 'vitest';
import { validateJweApu, validateJweApv } from '../validateJweApi';
import { JweInvalid } from '@/jose/errors/errors';

describe('validateJweApi', () => {
  describe('validateJweApu', () => {
    it('should return undefined for undefined input', () => {
      expect(validateJweApu(undefined)).toBeUndefined();
    });

    it('should return undefined for null input', () => {
      expect(validateJweApu(null)).toBeUndefined();
    });

    it('should return the same Uint8Array for valid input', () => {
      const input = new Uint8Array([1, 2, 3]);
      const result = validateJweApu(input);
      expect(result).toBe(input);
    });

    it('should throw JweInvalid for non-Uint8Array input', () => {
      expect(() => validateJweApu('invalid')).toThrow(
        new JweInvalid('"apu (Agreement PartyUInfo)" must be a Uint8Array'),
      );
    });

    it('should throw JweInvalid for input exceeding 32 bytes', () => {
      const input = new Uint8Array(33);
      expect(() => validateJweApu(input)).toThrow(
        new JweInvalid(
          '"apu (Agreement PartyUInfo)" must be less than or equal to 32 bytes',
        ),
      );
    });
  });

  describe('validateJweApv', () => {
    it('should return undefined for undefined input', () => {
      expect(validateJweApv(undefined)).toBeUndefined();
    });

    it('should return undefined for null input', () => {
      expect(validateJweApv(null)).toBeUndefined();
    });

    it('should return the same Uint8Array for valid input', () => {
      const input = new Uint8Array([1, 2, 3]);
      const result = validateJweApv(input);
      expect(result).toBe(input);
    });

    it('should throw JweInvalid for non-Uint8Array input', () => {
      expect(() => validateJweApv('invalid')).toThrow(
        new JweInvalid('"apv (Agreement PartyVInfo)" must be a Uint8Array'),
      );
    });

    it('should throw JweInvalid for input exceeding 32 bytes', () => {
      const input = new Uint8Array(33);
      expect(() => validateJweApv(input)).toThrow(
        new JweInvalid(
          '"apv (Agreement PartyVInfo)" must be less than or equal to 32 bytes',
        ),
      );
    });
  });
});
