import { describe, it, expect } from 'vitest';
import * as jose from 'jose';
import { FlattenedEncryption } from '../FlattenedEncryption';
import { JweInvalid } from '@/jose/errors/errors';
import { decodeBase64Url, encodeBase64Url } from 'u8a-utils';
import { JweHeaderParameters } from '../../types';

import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve, NistCurve } from 'noble-curves-extended';

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

  describe('validations', () => {
    it('should throw if plaintext is not Uint8Array', async () => {
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });
      await expect(
        encryption.encrypt(
          'not a Uint8Array' as unknown as Uint8Array,
          yourPublicKey,
        ),
      ).rejects.toThrow(TypeError);
    });

    it('should throw if yourPublicKey is invalid', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = new Uint8Array(33).fill(0); // 33 bytes of zeros is an invalid public key
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
      await expect(
        encryption.encrypt(plaintext, yourPublicKey),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when no header is set', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({ curve, aes });
      await expect(
        encryption.encrypt(plaintext, yourPublicKey),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when protected header is empty', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({});
      await expect(
        encryption.encrypt(plaintext, yourPublicKey),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when options.crit contains non-existent parameter', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', crit: ['hoge'] });
      await expect(
        encryption.encrypt(plaintext, yourPublicKey),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when alg is missing', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ enc: 'A256GCM' });
      await expect(
        encryption.encrypt(plaintext, yourPublicKey),
      ).rejects.toThrow(JweInvalid);
    });

    it('should throw JweInvalid when enc is missing', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES' });
      await expect(
        encryption.encrypt(plaintext, yourPublicKey),
      ).rejects.toThrow(JweInvalid);
    });
  });

  describe('headers', () => {
    it('should reflect unprotected and shared unprotected headers in JWE', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const unprotectedHeader = { kid: 'unprotected-key-id' };
      const sharedUnprotectedHeader = { cty: 'application/json' };
      const encryption = new FlattenedEncryption({ curve, aes })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader(unprotectedHeader)
        .sharedUnprotectedHeader(sharedUnprotectedHeader);
      const jwe = await encryption.encrypt(plaintext, yourPublicKey);
      expect(jwe.header).toEqual(unprotectedHeader);
      expect(jwe.unprotected).toEqual(sharedUnprotectedHeader);
    });
  });

  describe('method call restrictions', () => {
    it('should throw TypeError when keyManagementParameters is called twice', () => {
      const encryption = new FlattenedEncryption({ curve, aes });
      encryption.keyManagementParameters({ apu: new Uint8Array([1]) });
      expect(() => {
        encryption.keyManagementParameters({ apu: new Uint8Array([2]) });
      }).toThrow(TypeError);
    });

    it('should throw TypeError when protectedHeader is called twice', () => {
      const encryption = new FlattenedEncryption({ curve, aes });
      encryption.protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });
      expect(() => {
        encryption.protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });
      }).toThrow(TypeError);
    });

    it('should throw TypeError when sharedUnprotectedHeader is called twice', () => {
      const encryption = new FlattenedEncryption({ curve, aes });
      encryption.sharedUnprotectedHeader({ cty: 'application/json' });
      expect(() => {
        encryption.sharedUnprotectedHeader({ cty: 'text/plain' });
      }).toThrow(TypeError);
    });

    it('should throw TypeError when unprotectedHeader is called twice', () => {
      const encryption = new FlattenedEncryption({ curve, aes });
      encryption.unprotectedHeader({ kid: 'key-1' });
      expect(() => {
        encryption.unprotectedHeader({ kid: 'key-2' });
      }).toThrow(TypeError);
    });
  });

  describe('additionalAuthenticatedData', () => {
    it('should set AAD and return this for chaining', () => {
      const encryption = new FlattenedEncryption({ curve, aes });
      const aad = new TextEncoder().encode('test-aad');
      const result = encryption.additionalAuthenticatedData(aad);
      expect(result).toBe(encryption);
    });
  });

  describe('encrypt', () => {
    it('should include aad in JWE when it exists', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const aad = new TextEncoder().encode('test-aad');
      const encryption = new FlattenedEncryption({ curve, aes })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(aad);
      const jwe = await encryption.encrypt(plaintext, yourPublicKey);
      expect(jwe.aad).toBe(encodeBase64Url(aad));
    });

    it('should include unprotected and shared unprotected headers in JWE when they exist', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const unprotectedHeader = { kid: 'unprotected-key-id' };
      const sharedUnprotectedHeader = { cty: 'application/json' };
      const encryption = new FlattenedEncryption({ curve, aes })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader(unprotectedHeader)
        .sharedUnprotectedHeader(sharedUnprotectedHeader);
      const jwe = await encryption.encrypt(plaintext, yourPublicKey);
      expect(jwe.header).toEqual(unprotectedHeader);
      expect(jwe.unprotected).toEqual(sharedUnprotectedHeader);
    });

    it('should include iv and tag in JWE', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });
      const jwe = await encryption.encrypt(plaintext, yourPublicKey);
      expect(jwe.iv).toBeDefined();
      expect(jwe.tag).toBeDefined();
    });

    it('should include protected header in JWE', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const yourPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );
      const protectedHeader: JweHeaderParameters = {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      };
      const encryption = new FlattenedEncryption({
        curve,
        aes,
      }).protectedHeader(protectedHeader);
      const jwe = await encryption.encrypt(plaintext, yourPublicKey);
      expect(jwe.protected).toBeDefined();
      const decodedHeader = JSON.parse(atob(jwe.protected));
      expect(decodedHeader).toMatchObject(protectedHeader);
      expect(decodedHeader.epk).toMatchObject({
        crv: 'P-256',
        kty: 'EC',
      });
      expect(decodedHeader.epk.x).toBeDefined();
      expect(decodedHeader.epk.y).toBeDefined();
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
});
