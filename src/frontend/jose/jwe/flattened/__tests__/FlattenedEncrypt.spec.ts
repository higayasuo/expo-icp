import { describe, it, expect } from 'vitest';
import * as jose from 'jose';
import { FlattenedEncrypt } from '../FlattenedEncrypt';
import { JweInvalid, JoseNotSupported } from '@/jose/errors/errors';
import { fromB64U, toB64U } from 'u8a-utils';

import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const decoder = new TextDecoder();

const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('FlattenedEncrypt', () => {
  describe('constructor', () => {
    it('should throw TypeError when plaintext is not Uint8Array', () => {
      expect(() => {
        new FlattenedEncrypt({
          curve,
          aes,
          plaintext: 'not a Uint8Array' as unknown as Uint8Array,
        });
      }).toThrow('plaintext must be an Uint8Array');
    });

    it('should accept TextEncoder.encode() output', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      expect(() => {
        new FlattenedEncrypt({
          curve,
          aes,
          plaintext,
        });
      }).not.toThrow();
    });
  });

  describe('getValidatedAlgAndEnc', () => {
    it('should return valid alg and enc', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const { alg, enc } = encrypt.getValidatedAlgAndEnc();
      expect(alg).toBe('ECDH-ES');
      expect(enc).toBe('A256GCM');
    });

    it('should throw JweInvalid when protected header is missing', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      });

      expect(() => encrypt.getValidatedAlgAndEnc()).toThrow(
        new JweInvalid('JWE Protected Header Parameter missing'),
      );
    });

    it('should throw JweInvalid when alg is missing', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ enc: 'A256GCM' });

      expect(() => encrypt.getValidatedAlgAndEnc()).toThrow(
        new JweInvalid('JWE "alg" Parameter missing/invalid'),
      );
    });

    it('should throw JweInvalid when enc is missing', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES' });

      expect(() => encrypt.getValidatedAlgAndEnc()).toThrow(
        new JweInvalid('JWE "enc" Parameter missing/invalid'),
      );
    });

    it('should throw JweInvalid when enc is invalid', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'INVALID' });

      expect(() => encrypt.getValidatedAlgAndEnc()).toThrow(
        new JweInvalid('JWE "enc" Parameter missing/invalid'),
      );
    });
  });

  describe('buildJoseHeader', () => {
    it('should combine headers correctly', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader({ kid: 'test-key' })
        .sharedUnprotectedHeader({ cty: 'text/plain' });

      const header = encrypt.buildJoseHeader();
      expect(header).toEqual({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        kid: 'test-key',
        cty: 'text/plain',
      });
    });

    it('should throw JoseNotSupported when zip parameter is present', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM', zip: 'DEF' });

      expect(() => encrypt.buildJoseHeader()).toThrow(
        new JoseNotSupported(
          'JWE "zip" (Compression Algorithm) Header Parameter is not supported.',
        ),
      );
    });
  });

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

    const myJwe = await new FlattenedEncrypt({
      curve,
      aes,
      plaintext: new TextEncoder().encode('Hello, World!'),
    })
      .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(rawPublicKey);

    console.log(myJwe);

    // Decrypt
    const decrypted = await jose.flattenedDecrypt(jwe, privateKey);
    const myDecrypted = await jose.flattenedDecrypt(myJwe, privateKey);

    // Verify
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello, World!');
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

    const myJwe = await new FlattenedEncrypt({
      curve,
      aes,
      plaintext: new TextEncoder().encode('Hello, World!'),
    })
      .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .keyManagementParameters({ apu, apv })
      .encrypt(rawPublicKey);

    console.log(myJwe);

    // Decrypt
    const decrypted = await jose.flattenedDecrypt(jwe, privateKey);
    const myDecrypted = await jose.flattenedDecrypt(myJwe, privateKey);

    // Verify
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello, World!');
    expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
      'Hello, World!',
    );
  });

  describe('verifyHeaders', () => {
    it('should throw JweInvalid when no header is set', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      });

      await expect(encrypt.encrypt(rawPublicKey)).rejects.toThrow(
        new JweInvalid(
          'either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()',
        ),
      );
    });

    it('should throw JweInvalid when headers have duplicate keys', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPublicKey = curve.getPublicKey(
        curve.utils.randomPrivateKey(),
        false,
      );

      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader({ alg: 'ECDH-ES' }); // duplicate 'alg' key

      await expect(encrypt.encrypt(rawPublicKey)).rejects.toThrow(
        new JweInvalid(
          'JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint',
        ),
      );
    });
  });

  describe('updateProtectedHeader', () => {
    it('should create new protected header when none exists', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      });

      const parameters = { alg: 'ECDH-ES', enc: 'A256GCM' };
      encrypt.updateProtectedHeader(parameters);

      const { alg, enc } = encrypt.getValidatedAlgAndEnc();
      expect(alg).toBe('ECDH-ES');
      expect(enc).toBe('A256GCM');
    });

    it('should merge parameters with existing protected header', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const parameters = { kid: 'test-key', cty: 'text/plain' };
      encrypt.updateProtectedHeader(parameters);

      const header = encrypt.buildJoseHeader();
      expect(header).toEqual({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
        kid: 'test-key',
        cty: 'text/plain',
      });
    });

    it('should not modify protected header when parameters are undefined', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      encrypt.updateProtectedHeader(undefined);

      const { alg, enc } = encrypt.getValidatedAlgAndEnc();
      expect(alg).toBe('ECDH-ES');
      expect(enc).toBe('A256GCM');
    });
  });

  describe('buildProtectedHeaderB64U', () => {
    it('should return Base64URL encoded string when protected header exists', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const protectedHeaderB64U = encrypt.buildProtectedHeaderB64U();
      const decoded = JSON.parse(decoder.decode(fromB64U(protectedHeaderB64U)));

      expect(decoded).toEqual({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
    });

    it('should return empty string when no protected header exists', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      });

      const protectedHeaderB64U = encrypt.buildProtectedHeaderB64U();
      expect(protectedHeaderB64U).toBe('');
    });
  });

  describe('buildAadB64U', () => {
    it('should return concatenated string when AAD exists', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      })
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(new TextEncoder().encode('test-aad'));

      const protectedHeaderB64U = encrypt.buildProtectedHeaderB64U();
      const aadB64U = encrypt.buildAadB64U(protectedHeaderB64U);

      // Verify the format: protectedHeaderB64U.aadB64U
      const [header, aad] = aadB64U.split('.');
      expect(header).toBe(protectedHeaderB64U);
      expect(aad).toBe(toB64U(new TextEncoder().encode('test-aad')));
    });

    it('should return only protected header when no AAD exists', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });

      const protectedHeaderB64U = encrypt.buildProtectedHeaderB64U();
      const aadB64U = encrypt.buildAadB64U(protectedHeaderB64U);

      expect(aadB64U).toBe(protectedHeaderB64U);
    });

    it('should handle empty protected header', () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const encrypt = new FlattenedEncrypt({
        curve,
        aes,
        plaintext,
      }).additionalAuthenticatedData(new TextEncoder().encode('test-aad'));

      const protectedHeaderB64U = encrypt.buildProtectedHeaderB64U();
      const aadB64U = encrypt.buildAadB64U(protectedHeaderB64U);

      // When protected header is empty, it should still include the dot
      expect(aadB64U).toBe(`.${toB64U(new TextEncoder().encode('test-aad'))}`);
    });
  });
});
