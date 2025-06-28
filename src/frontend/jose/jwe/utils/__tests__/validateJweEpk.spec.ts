import { describe, expect, it } from 'vitest';
import { validateJweEpk } from '../validateJweEpk';
import { JweInvalid } from '@/jose/errors';
import { Jwk } from '@/jose/types';
import { encodeBase64Url } from 'u8a-utils';

describe('validateJweEpk', () => {
  // P-256: 32 bytes each for x and y
  const validEcEpk: Jwk = {
    kty: 'EC',
    crv: 'P-256',
    x: encodeBase64Url(new Uint8Array(32)), // 32 bytes base64url encoded
    y: encodeBase64Url(new Uint8Array(32)), // 32 bytes base64url encoded
  };

  // X25519: 32 bytes for x
  const validOkpEpk: Jwk = {
    kty: 'OKP',
    crv: 'X25519',
    x: encodeBase64Url(new Uint8Array(32)), // 32 bytes base64url encoded
  };

  describe('valid ephemeral public keys', () => {
    it('should validate a valid EC ephemeral public key', () => {
      const result = validateJweEpk(validEcEpk);
      expect(result).toEqual(validEcEpk);
    });

    it('should validate a valid OKP ephemeral public key', () => {
      const result = validateJweEpk(validOkpEpk);
      expect(result).toEqual(validOkpEpk);
    });

    it('should validate EC keys with different supported curves', () => {
      const curves = ['P-256', 'P-384', 'P-521'] as const;
      curves.forEach((crv) => {
        // Generate appropriate key lengths for each curve
        let x: string, y: string;
        switch (crv) {
          case 'P-256':
            x = encodeBase64Url(new Uint8Array(32)); // 32 bytes base64url encoded
            y = encodeBase64Url(new Uint8Array(32)); // 32 bytes base64url encoded
            break;
          case 'P-384':
            x = encodeBase64Url(new Uint8Array(48)); // 48 bytes base64url encoded
            y = encodeBase64Url(new Uint8Array(48)); // 48 bytes base64url encoded
            break;
          case 'P-521':
            x = encodeBase64Url(new Uint8Array(66)); // 66 bytes base64url encoded
            y = encodeBase64Url(new Uint8Array(66)); // 66 bytes base64url encoded
            break;
          default:
            throw new Error(`Unsupported curve: ${crv}`);
        }

        const epk = { ...validEcEpk, crv, x, y };
        const result = validateJweEpk(epk);
        expect(result).toEqual(epk);
      });
    });

    it('should validate OKP keys with X25519 curve', () => {
      const epk = { ...validOkpEpk, crv: 'X25519' };
      const result = validateJweEpk(epk);
      expect(result).toEqual(epk);
    });

    it('should not require y for OKP keys', () => {
      const okpEpkWithoutY = { ...validOkpEpk };
      delete (okpEpkWithoutY as any).y;
      const result = validateJweEpk(okpEpkWithoutY);
      expect(result).toEqual(okpEpkWithoutY);
    });
  });

  describe('invalid inputs', () => {
    it('should throw JweInvalid when epk is null or undefined', () => {
      expect(() => validateJweEpk(undefined)).toThrow(
        new JweInvalid('"epk" (Ephemeral Public Key) is missing'),
      );
      expect(() => validateJweEpk(null)).toThrow(
        new JweInvalid('"epk" (Ephemeral Public Key) is missing'),
      );
    });

    it('should throw JweInvalid when epk is not a plain object', () => {
      const invalidEpks = ['string', 123, true, [], new Date(), () => {}];

      invalidEpks.forEach((epk) => {
        expect(() => validateJweEpk(epk)).toThrow(
          new JweInvalid('"epk" (Ephemeral Public Key) is not a plain object'),
        );
      });
    });

    it('should throw JweInvalid when kty is not EC or OKP', () => {
      const invalidEpks = [
        { ...validEcEpk, kty: 'RSA' },
        { ...validEcEpk, kty: 'oct' },
        { ...validEcEpk, kty: 'invalid' },
      ];

      invalidEpks.forEach((epk) => {
        expect(() => validateJweEpk(epk)).toThrow(
          new JweInvalid('The kty of "epk" (Ephemeral Public Key) is invalid'),
        );
      });
    });

    it('should throw JweInvalid when crv is invalid', () => {
      const invalidEpks = [
        { ...validEcEpk, crv: 'P-128' },
        { ...validEcEpk, crv: 'secp256k1' },
        { ...validEcEpk, crv: 'invalid' },
        { ...validEcEpk, crv: undefined },
        { ...validOkpEpk, crv: 'Ed25519' },
        { ...validOkpEpk, crv: 'invalid' },
      ];

      invalidEpks.forEach((epk) => {
        expect(() => validateJweEpk(epk)).toThrow(
          new JweInvalid('The crv of "epk" (Ephemeral Public Key) is invalid'),
        );
      });
    });

    it('should throw JweInvalid when x is invalid', () => {
      const invalidEpks = [
        { ...validEcEpk, x: undefined },
        { ...validEcEpk, x: 'invalid!' },
        { ...validEcEpk, x: 123 },
        { ...validOkpEpk, x: undefined },
        { ...validOkpEpk, x: 'invalid!' },
        { ...validOkpEpk, x: 123 },
      ];

      invalidEpks.forEach((epk) => {
        expect(() => validateJweEpk(epk)).toThrow(
          new JweInvalid('"The x of "epk" (Ephemeral Public Key)" is invalid'),
        );
      });
    });

    it('should throw JweInvalid when y is missing for EC keys', () => {
      const invalidEpks = [
        { ...validEcEpk, y: undefined },
        { ...validEcEpk, y: 'invalid!' },
        { ...validEcEpk, y: 123 },
      ];

      invalidEpks.forEach((epk) => {
        expect(() => validateJweEpk(epk)).toThrow(
          new JweInvalid('"The y of "epk" (Ephemeral Public Key)" is invalid'),
        );
      });
    });
  });
});
