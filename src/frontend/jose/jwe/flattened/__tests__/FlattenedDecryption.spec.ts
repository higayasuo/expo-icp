import { describe, it, expect } from 'vitest';
import { FlattenedEncryption } from '../FlattenedEncryption';
import { FlattenedDecryption } from '../FlattenedDecryption';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';
import { encodeBase64Url } from 'u8a-utils';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('FlattenedDecryption', () => {
  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt with ECDH-ES and A256GCM', async () => {
      // Generate key pair
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

      // Create plaintext
      const plaintext = new TextEncoder().encode('Hello, World!');

      // Encrypt
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);

      // Decrypt
      const decryption = new FlattenedDecryption({
        curve,
        aes,
      });

      const decrypted = await decryption.decrypt(jwe, rawPrivateKey);

      // Verify
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
        'Hello, World!',
      );
      expect(decrypted.protectedHeader!).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
      expect(decrypted.protectedHeader!.epk).toMatchObject({
        crv: 'P-256',
        kty: 'EC',
      });
      expect(decrypted.protectedHeader!.epk!.x).toBeDefined();
      expect(decrypted.protectedHeader!.epk!.y).toBeDefined();
      expect(decrypted.additionalAuthenticatedData).toBeUndefined();
      expect(decrypted.sharedUnprotectedHeader).toBeUndefined();
      expect(decrypted.unprotectedHeader).toBeUndefined();

      // Verify JWE structure
      expect(jwe.protected).toBeDefined();
      expect(jwe.iv).toBeDefined();
      expect(jwe.ciphertext).toBeDefined();
      expect(jwe.tag).toBeDefined();
    });

    it('should encrypt and decrypt with apu/apv parameters', async () => {
      // Generate key pair
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

      // Create plaintext
      const plaintext = new TextEncoder().encode('Hello, World!');

      // Create apu/apv
      const apu = new TextEncoder().encode('Alice');
      const apv = new TextEncoder().encode('Bob');

      // Encrypt
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .keyManagementParameters({ apu, apv });

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);

      // Decrypt
      const decryption = new FlattenedDecryption({
        curve,
        aes,
      });

      const decrypted = await decryption.decrypt(jwe, rawPrivateKey);

      // Verify
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
        'Hello, World!',
      );
      expect(decrypted.protectedHeader!).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        apu: encodeBase64Url(apu),
        apv: encodeBase64Url(apv),
      });
      expect(decrypted.protectedHeader!.epk).toMatchObject({
        crv: 'P-256',
        kty: 'EC',
      });
      expect(decrypted.protectedHeader!.epk!.x).toBeDefined();
      expect(decrypted.protectedHeader!.epk!.y).toBeDefined();
      expect(decrypted.additionalAuthenticatedData).toBeUndefined();
      expect(decrypted.sharedUnprotectedHeader).toBeUndefined();
      expect(decrypted.unprotectedHeader).toBeUndefined();

      // Verify JWE structure
      expect(jwe.protected).toBeDefined();
      expect(jwe.iv).toBeDefined();
      expect(jwe.ciphertext).toBeDefined();
      expect(jwe.tag).toBeDefined();
    });
  });
});
