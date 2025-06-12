import { describe, it, expect } from 'vitest';
import * as jose from 'jose';
import { FlattenedEncryption } from '../FlattenedEncryption';
import { JweInvalid, JweNotSupported } from '@/jose/errors/errors';
import { decodeBase64Url, encodeBase64Url } from 'u8a-utils';

import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const decoder = new TextDecoder();

const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('FlattenedEncryption', () => {
  describe('encrypt and decrypt', () => {
    it('should encrypt and decrypt with ECDH-ES and A256GCM', async () => {
      // Generate key pair
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);
      const publicKey = await jose.importJWK(jwkPublicKey, 'ECDH-ES');
      const privateKey = await jose.importJWK(jwkPrivateKey, 'ECDH-ES');

      // Create plaintext
      const plaintext = Uint8Array.from(
        new TextEncoder().encode('Hello, World!'),
      );

      // Encrypt
      const jwe = await new jose.FlattenedEncrypt(plaintext)
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(publicKey);

      const myJwe = await new FlattenedEncryption({
        curve,
        aes,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, rawPublicKey);

      console.log(myJwe);

      // Decrypt
      const decrypted = await jose.flattenedDecrypt(jwe, privateKey);
      const myDecrypted = await jose.flattenedDecrypt(myJwe, privateKey);

      // Verify
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
        'Hello, World!',
      );
      expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
        'Hello, World!',
      );
    });

    it('should encrypt and decrypt with apu/apv parameters', async () => {
      // Generate key pair
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);
      const publicKey = await jose.importJWK(jwkPublicKey, 'ECDH-ES');
      const privateKey = await jose.importJWK(jwkPrivateKey, 'ECDH-ES');

      // Create plaintext
      const plaintext = Uint8Array.from(
        new TextEncoder().encode('Hello, World!'),
      );

      // Create apu/apv
      const apu = Uint8Array.from(new TextEncoder().encode('Alice'));
      const apv = Uint8Array.from(new TextEncoder().encode('Bob'));

      // Encrypt
      const jwe = await new jose.FlattenedEncrypt(plaintext)
        .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .setKeyManagementParameters({ apu, apv })
        .encrypt(publicKey);

      const myJwe = await new FlattenedEncryption({
        curve,
        aes,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .keyManagementParameters({ apu, apv })
        .encrypt(plaintext, rawPublicKey);

      console.log(myJwe);

      // Decrypt
      const decrypted = await jose.flattenedDecrypt(jwe, privateKey);
      const myDecrypted = await jose.flattenedDecrypt(myJwe, privateKey);

      // Verify
      expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
        'Hello, World!',
      );
      expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
        'Hello, World!',
      );
    });
  });

  describe('constructor', () => {
    it('should accept curve and aes', () => {
      expect(() => {
        new FlattenedEncryption({
          curve,
          aes,
        });
      }).not.toThrow();
    });
  });

  describe('headers', () => {
    it('should throw JweInvalid when no header is set', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      });

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when protected header is empty', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({});

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when alg is missing', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ enc: 'A256GCM' });

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweInvalid when enc is missing', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES' });

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweInvalid,
      );
    });

    it('should throw JweNotSupported when alg is invalid', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'INVALID' as any, enc: 'A256GCM' });

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweNotSupported,
      );
    });

    it('should throw JweNotSupported when enc is invalid', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'INVALID' as any });

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweNotSupported,
      );
    });

    it('should throw JweInvalid when headers have duplicate keys', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader({ alg: 'ECDH-ES' }); // duplicate 'alg' key

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweInvalid,
      );
    });
  });

  describe('updateProtectedHeader', () => {
    it('should merge parameters with existing protected header', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const parameters = { kid: 'test-key', cty: 'text/plain' };
      encryption.updateProtectedHeader(parameters);

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);
      expect(jwe.protected).toBeDefined();
      const decoded = JSON.parse(
        decoder.decode(decodeBase64Url(jwe.protected!)),
      );
      expect(decoded).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        kid: 'test-key',
        cty: 'text/plain',
      });
    });

    it('should create new protected header when none exists', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      });

      const parameters = { alg: 'ECDH-ES' as const, enc: 'A256GCM' as const };
      encryption.updateProtectedHeader(parameters);

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);
      expect(jwe.protected).toBeDefined();
      const decoded = JSON.parse(
        decoder.decode(decodeBase64Url(jwe.protected!)),
      );
      expect(decoded).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
    });

    it('should not modify protected header when parameters are undefined', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      encryption.updateProtectedHeader(undefined);

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);
      expect(jwe.protected).toBeDefined();
      const decoded = JSON.parse(
        decoder.decode(decodeBase64Url(jwe.protected!)),
      );
      expect(decoded).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
    });
  });

  describe('buildAadB64U', () => {
    it('should return concatenated string when AAD exists', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(new TextEncoder().encode('test-aad'));

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);
      expect(jwe.aad).toBeDefined();
      expect(jwe.aad).toBe(
        encodeBase64Url(new TextEncoder().encode('test-aad')),
      );
    });

    it('should return only protected header when no AAD exists', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const jwe = await encryption.encrypt(plaintext, rawPublicKey);
      expect(jwe.aad).toBeUndefined();
      expect(jwe.protected).toBeDefined();
    });

    it('should handle empty protected header', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).additionalAuthenticatedData(new TextEncoder().encode('test-aad'));

      await expect(encryption.encrypt(plaintext, rawPublicKey)).rejects.toThrow(
        JweInvalid,
      );
    });
  });
});
