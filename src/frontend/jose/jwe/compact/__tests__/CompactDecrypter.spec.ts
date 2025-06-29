import { describe, expect, it } from 'vitest';
import { CompactEncrypter } from '../CompactEncrypter';
import { CompactDecrypter } from '../CompactDecrypter';
import { randomBytes } from '@noble/hashes/utils';
import { WebAesCipher } from 'aes-universal-web';
import { JweInvalid } from '@/jose/errors/errors';
import { createEcdhCurve } from 'noble-curves-extended';

const aes = new WebAesCipher(randomBytes);
const curve = createEcdhCurve('P-256', randomBytes);

describe('CompactDecryption', () => {
  describe('decrypt', () => {
    it('should decrypt data encrypted by CompactEncryption', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

      const compactJwe = await new CompactEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, jwkPublicKey);

      const result = await new CompactDecrypter(aes).decrypt(
        compactJwe,
        jwkPrivateKey,
      );
      expect(new TextDecoder().decode(result.plaintext)).toBe('Hello, World!');
      expect(result.protectedHeader).toEqual({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        epk: expect.objectContaining({
          kty: 'EC',
          crv: 'P-256',
          x: expect.any(String),
          y: expect.any(String),
        }),
      });
    });
  });

  describe('validations', () => {
    it('should throw JweInvalid when compactJwe is not a string', async () => {
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactDecrypter(aes).decrypt(123 as any, jwkPrivateKey),
      ).rejects.toThrow(new JweInvalid('Compact JWE must be a string'));
    });

    it('should throw JweInvalid when compactJwe has invalid format', async () => {
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactDecrypter(aes).decrypt('invalid.jwe.format', jwkPrivateKey),
      ).rejects.toThrow(
        new JweInvalid('Invalid Compact JWE: must have 5 parts'),
      );
    });

    it('should throw JweInvalid when protected header is missing', async () => {
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactDecrypter(aes).decrypt(
          '.encrypted_key.iv.ciphertext.tag',
          jwkPrivateKey,
        ),
      ).rejects.toThrow(
        new JweInvalid('Invalid Compact JWE: protected header is missing'),
      );
    });

    it('should throw JweInvalid when iv is missing', async () => {
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactDecrypter(aes).decrypt(
          'protected.encrypted_key..ciphertext.tag',
          jwkPrivateKey,
        ),
      ).rejects.toThrow(new JweInvalid('Invalid Compact JWE: iv is missing'));
    });

    it('should throw JweInvalid when ciphertext is missing', async () => {
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactDecrypter(aes).decrypt(
          'protected.encrypted_key.iv..tag',
          jwkPrivateKey,
        ),
      ).rejects.toThrow(
        new JweInvalid('Invalid Compact JWE: ciphertext is missing'),
      );
    });

    it('should throw JweInvalid when tag is missing', async () => {
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactDecrypter(aes).decrypt(
          'protected.encrypted_key.iv.ciphertext.',
          jwkPrivateKey,
        ),
      ).rejects.toThrow(new JweInvalid('Invalid Compact JWE: tag is missing'));
    });
  });
});
