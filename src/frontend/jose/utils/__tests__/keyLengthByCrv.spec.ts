import { describe, it, expect } from 'vitest';
import { keyLengthByCrv } from '../keyLengthByCrv';
import { JoseNotSupported } from '../../errors';

describe('keyLengthByCrv', () => {
  describe('supported curves', () => {
    it('should return correct key length for P-256', () => {
      expect(keyLengthByCrv('P-256')).toBe(32);
    });

    it('should return correct key length for P-384', () => {
      expect(keyLengthByCrv('P-384')).toBe(48);
    });

    it('should return correct key length for P-521', () => {
      expect(keyLengthByCrv('P-521')).toBe(66);
    });

    it('should return correct key length for secp256k1', () => {
      expect(keyLengthByCrv('secp256k1')).toBe(32);
    });

    it('should return correct key length for Ed25519', () => {
      expect(keyLengthByCrv('Ed25519')).toBe(32);
    });

    it('should return correct key length for X25519', () => {
      expect(keyLengthByCrv('X25519')).toBe(32);
    });
  });

  describe('unsupported curves', () => {
    it('should throw JoseNotSupported for unsupported curves', () => {
      const unsupportedCurves = [
        'P-128', // Non-existent curve
        'secp384r1', // Different naming convention
        'brainpoolP256r1', // Brainpool curve
        'invalid-curve', // Completely invalid
        '', // Empty string
      ];

      unsupportedCurves.forEach((crv) => {
        expect(() => keyLengthByCrv(crv)).toThrow(
          new JoseNotSupported(
            `The specified "crv" (Curve) is not supported: ${crv}`,
          ),
        );
      });
    });
  });

  describe('edge cases', () => {
    it('should handle non-string inputs', () => {
      expect(() => keyLengthByCrv(null as any)).toThrow(
        new JoseNotSupported(
          'The specified "crv" (Curve) is not supported: null',
        ),
      );
      expect(() => keyLengthByCrv(undefined as any)).toThrow(
        new JoseNotSupported(
          'The specified "crv" (Curve) is not supported: undefined',
        ),
      );
      expect(() => keyLengthByCrv(123 as any)).toThrow(
        new JoseNotSupported(
          'The specified "crv" (Curve) is not supported: 123',
        ),
      );
    });
  });
});
