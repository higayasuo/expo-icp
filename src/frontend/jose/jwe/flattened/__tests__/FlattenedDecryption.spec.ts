import { describe, it, expect } from 'vitest';
import { FlattenedEncryption } from '../FlattenedEncryption';
import { FlattenedDecryption } from '../FlattenedDecryption';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';
import { encodeBase64Url } from 'u8a-utils';
import { JweInvalid } from '@/jose/errors/errors';
import { FlattenedJwe } from '../../types';

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

  describe('decrypt validations', () => {
    it('should throw JweInvalid when jwe is not a plain object', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = null;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt(jwe as any, rawPrivateKey),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when private key is invalid', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
        protected: 'protected',
      } as FlattenedJwe;
      const invalidPrivateKey = new Uint8Array(32).fill(0);

      await expect(decryption.decrypt(jwe, invalidPrivateKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when protected header is missing', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
      } as FlattenedJwe;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(decryption.decrypt(jwe, rawPrivateKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when options.crit contains non-existent parameter', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM', crit: ['hoge'] }),
          ),
        ),
      } as FlattenedJwe;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(decryption.decrypt(jwe, rawPrivateKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when alg is missing', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
        protected: encodeBase64Url(
          new TextEncoder().encode(JSON.stringify({ enc: 'A256GCM' })),
        ),
      } as FlattenedJwe;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(decryption.decrypt(jwe, rawPrivateKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when enc is missing', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
        protected: encodeBase64Url(
          new TextEncoder().encode(JSON.stringify({ alg: 'ECDH-ES' })),
        ),
      } as FlattenedJwe;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(decryption.decrypt(jwe, rawPrivateKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when alg is not in keyManagementAlgorithms', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
      } as FlattenedJwe;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt(jwe, rawPrivateKey, {
          keyManagementAlgorithms: ['RSA-OAEP'],
        }),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when enc is not in contentEncryptionAlgorithms', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const jwe = {
        ciphertext: 'ciphertext',
        iv: 'iv',
        tag: 'tag',
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
      } as FlattenedJwe;
      const rawPrivateKey = curve.utils.randomPrivateKey();

      await expect(
        decryption.decrypt(jwe, rawPrivateKey, {
          contentEncryptionAlgorithms: ['A128CBC-HS256'],
        }),
      ).rejects.toThrow(JweInvalid);
    });
  });

  describe('decrypt results', () => {
    it('should include aad in decrypted result when it exists', async () => {
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const aad = new TextEncoder().encode('test-aad');

      const encryption = new FlattenedEncryption({ curve, aes })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(aad);

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);

      const decryption = new FlattenedDecryption({ curve, aes });
      const decrypted = await decryption.decrypt(jwe, rawPrivateKey);

      expect(decrypted.additionalAuthenticatedData).toEqual(
        Uint8Array.from(aad),
      );
    });

    it('should include shared unprotected header in decrypted result when it exists', async () => {
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const sharedUnprotectedHeader = { test: 'value' };

      const encryption = new FlattenedEncryption({ curve, aes })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .sharedUnprotectedHeader(sharedUnprotectedHeader);

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);

      const decryption = new FlattenedDecryption({ curve, aes });
      const decrypted = await decryption.decrypt(jwe, rawPrivateKey);

      expect(decrypted.sharedUnprotectedHeader).toEqual(
        sharedUnprotectedHeader,
      );
    });

    it('should include unprotected header in decrypted result when it exists', async () => {
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const unprotectedHeader = { test: 'value' };

      const encryption = new FlattenedEncryption({ curve, aes })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader(unprotectedHeader);

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);

      const decryption = new FlattenedDecryption({ curve, aes });
      const decrypted = await decryption.decrypt(jwe, rawPrivateKey);

      expect(decrypted.unprotectedHeader).toEqual(unprotectedHeader);
    });

    it('should include protectedHeader in result', async () => {
      const decryption = new FlattenedDecryption({ curve, aes });
      const encryption = new FlattenedEncryption({ curve, aes });
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

      const jwe = await encryption
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, rawPublicKey);

      const result = await decryption.decrypt(jwe, rawPrivateKey);
      expect(result.protectedHeader).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
    });
  });
});
