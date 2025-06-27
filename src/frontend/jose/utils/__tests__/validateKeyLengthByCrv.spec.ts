import { describe, it, expect } from 'vitest';
import { validateKeyLengthByCrv } from '../validateKeyLengthByCrv';
import { JoseInvalid } from '../../errors';

describe('validateKeyLengthByCrv', () => {
  describe('valid key lengths', () => {
    it('should not throw for valid P-256 key length', () => {
      const key = new Uint8Array(32); // 32 bytes for P-256
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-256', label: 'x' }),
      ).not.toThrow();
    });

    it('should not throw for valid P-384 key length', () => {
      const key = new Uint8Array(48); // 48 bytes for P-384
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-384', label: 'y' }),
      ).not.toThrow();
    });

    it('should not throw for valid P-521 key length', () => {
      const key = new Uint8Array(66); // 66 bytes for P-521
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-521', label: 'd' }),
      ).not.toThrow();
    });

    it('should not throw for valid secp256k1 key length', () => {
      const key = new Uint8Array(32); // 32 bytes for secp256k1
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'secp256k1', label: 'x' }),
      ).not.toThrow();
    });

    it('should not throw for valid Ed25519 key length', () => {
      const key = new Uint8Array(32); // 32 bytes for Ed25519
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'Ed25519', label: 'x' }),
      ).not.toThrow();
    });

    it('should not throw for valid X25519 key length', () => {
      const key = new Uint8Array(32); // 32 bytes for X25519
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'X25519', label: 'x' }),
      ).not.toThrow();
    });
  });

  describe('missing key', () => {
    it('should throw JoseInvalid when key is null', () => {
      expect(() =>
        validateKeyLengthByCrv({ key: null as any, crv: 'P-256', label: 'x' }),
      ).toThrow(new JoseInvalid('"x" is missing'));
    });

    it('should throw JoseInvalid when key is undefined', () => {
      expect(() =>
        validateKeyLengthByCrv({
          key: undefined as any,
          crv: 'P-256',
          label: 'y',
        }),
      ).toThrow(new JoseInvalid('"y" is missing'));
    });
  });

  describe('invalid key lengths', () => {
    it('should throw JoseInvalid for P-256 with wrong key length', () => {
      const key = new Uint8Array(48); // Wrong length for P-256 (should be 32)
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-256', label: 'x' }),
      ).toThrow(new JoseInvalid('"x" is invalid'));
    });

    it('should throw JoseInvalid for P-384 with wrong key length', () => {
      const key = new Uint8Array(32); // Wrong length for P-384 (should be 48)
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-384', label: 'y' }),
      ).toThrow(new JoseInvalid('"y" is invalid'));
    });

    it('should throw JoseInvalid for P-521 with wrong key length', () => {
      const key = new Uint8Array(32); // Wrong length for P-521 (should be 66)
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-521', label: 'd' }),
      ).toThrow(new JoseInvalid('"d" is invalid'));
    });

    it('should throw JoseInvalid for empty key', () => {
      const key = new Uint8Array(0); // Empty key
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-256', label: 'x' }),
      ).toThrow(new JoseInvalid('"x" is invalid'));
    });
  });

  describe('error message labels', () => {
    it('should use correct label in error message for missing key', () => {
      expect(() =>
        validateKeyLengthByCrv({
          key: null as any,
          crv: 'P-256',
          label: 'custom-label',
        }),
      ).toThrow(new JoseInvalid('"custom-label" is missing'));
    });

    it('should use correct label in error message for invalid key length', () => {
      const key = new Uint8Array(48); // Wrong length for P-256
      expect(() =>
        validateKeyLengthByCrv({ key, crv: 'P-256', label: 'custom-label' }),
      ).toThrow(new JoseInvalid('"custom-label" is invalid'));
    });
  });
});
