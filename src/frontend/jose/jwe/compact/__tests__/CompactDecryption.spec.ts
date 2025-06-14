import { describe, expect, it } from 'vitest';
import { CompactEncryption } from '../CompactEncryption';
import { CompactDecryption } from '../CompactDecryption';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';
import { JweInvalid } from '@/jose/errors/errors';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('CompactDecryption', () => {
  describe('decrypt', () => {
    it('should decrypt data encrypted by CompactEncryption', async () => {
      const encryption = new CompactEncryption({ curve, aes });
      const decryption = new CompactDecryption({ curve, aes });
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

      const compactJwe = await encryption
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, rawPublicKey);

      const result = await decryption.decrypt(compactJwe, rawPrivateKey);
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
      const decryption = new CompactDecryption({ curve, aes });
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt(123 as any, rawPrivateKey),
      ).rejects.toThrow(new JweInvalid('Compact JWE must be a string'));
    });

    it('should throw JweInvalid when compactJwe has invalid format', async () => {
      const decryption = new CompactDecryption({ curve, aes });
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt('invalid.jwe.format', rawPrivateKey),
      ).rejects.toThrow(
        new JweInvalid('Invalid Compact JWE: must have 5 parts'),
      );
    });

    it('should throw JweInvalid when protected header is missing', async () => {
      const decryption = new CompactDecryption({ curve, aes });
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt('.encrypted_key.iv.ciphertext.tag', rawPrivateKey),
      ).rejects.toThrow(
        new JweInvalid('Invalid Compact JWE: protected header is required'),
      );
    });

    it('should throw JweInvalid when iv is missing', async () => {
      const decryption = new CompactDecryption({ curve, aes });
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt(
          'protected.encrypted_key..ciphertext.tag',
          rawPrivateKey,
        ),
      ).rejects.toThrow(new JweInvalid('Invalid Compact JWE: iv is required'));
    });

    it('should throw JweInvalid when ciphertext is missing', async () => {
      const decryption = new CompactDecryption({ curve, aes });
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt('protected.encrypted_key.iv..tag', rawPrivateKey),
      ).rejects.toThrow(
        new JweInvalid('Invalid Compact JWE: ciphertext is required'),
      );
    });

    it('should throw JweInvalid when tag is missing', async () => {
      const decryption = new CompactDecryption({ curve, aes });
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt(
          'protected.encrypted_key.iv.ciphertext.',
          rawPrivateKey,
        ),
      ).rejects.toThrow(new JweInvalid('Invalid Compact JWE: tag is required'));
    });
  });
});
