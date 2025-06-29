import { describe, it, expect } from 'vitest';
import * as jose from 'jose';
import { FlattenedEncrypter } from '../FlattenedEncrypter';
import { JweInvalid } from '@/jose/errors/errors';
import { decodeBase64Url, encodeBase64Url } from 'u8a-utils';
import { JweHeaderParameters } from '../../types';

import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createEcdhCurve, EcdhCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const decoder = new TextDecoder();

const p256 = createEcdhCurve('P-256', getRandomBytes);
const x25519 = createEcdhCurve('X25519', getRandomBytes);
const curve = p256;
const curves = [
  { curve: p256, curveName: p256.curveName as string },
  { curve: x25519, curveName: x25519.curveName as string },
];
const aes = new WebAesCipher(getRandomBytes);

describe('FlattenedEncrypter', () => {
  describe('encrypt and decrypt', () => {
    it.each(curves)(
      'should encrypt and decrypt with ECDH-ES and A256GCM using $curveName',
      async ({ curve }) => {
        // Generate key pair
        const rawPrivateKey = curve.randomPrivateKey();
        const rawPublicKey = curve.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);
        const josePublicKey = await jose.importJWK(jwkPublicKey, 'ECDH-ES');
        const josePrivateKey = await jose.importJWK(jwkPrivateKey, 'ECDH-ES');

        // Create plaintext
        const plaintext = Uint8Array.from(
          new TextEncoder().encode('Hello, World!'),
        );

        // Encrypt
        const jwe = await new jose.FlattenedEncrypt(plaintext)
          .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .encrypt(josePublicKey);

        const myJwe = await new FlattenedEncrypter(aes)
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .encrypt(plaintext, jwkPublicKey);

        // Decrypt
        const decrypted = await jose.flattenedDecrypt(jwe, josePrivateKey);
        const myDecrypted = await jose.flattenedDecrypt(myJwe, josePrivateKey);

        // Verify
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          'Hello, World!',
        );
        expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
          'Hello, World!',
        );
      },
    );

    it.each(curves)(
      'should encrypt and decrypt with apu/apv parameters using $curveName',
      async ({ curve }) => {
        // Generate key pair
        const rawPrivateKey = curve.randomPrivateKey();
        const rawPublicKey = curve.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);
        const josePublicKey = await jose.importJWK(jwkPublicKey, 'ECDH-ES');
        const josePrivateKey = await jose.importJWK(jwkPrivateKey, 'ECDH-ES');

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
          .encrypt(josePublicKey);

        const myJwe = await new FlattenedEncrypter(aes)
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .keyManagementParameters({ apu, apv })
          .encrypt(plaintext, jwkPublicKey);

        // Decrypt
        const decrypted = await jose.flattenedDecrypt(jwe, josePrivateKey);
        const myDecrypted = await jose.flattenedDecrypt(myJwe, josePrivateKey);

        // Verify
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          'Hello, World!',
        );
        expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
          'Hello, World!',
        );
      },
    );
  });

  describe('constructor', () => {
    it('should accept aes', () => {
      expect(() => {
        new FlattenedEncrypter(aes);
      }).not.toThrow();
    });
  });

  describe('validations', () => {
    describe('input parameter validation', () => {
      it('should throw if plaintext is not Uint8Array', async () => {
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
            })
            .encrypt('not a Uint8Array' as unknown as Uint8Array, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw if plaintext is missing', async () => {
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
            })
            .encrypt(null as unknown as Uint8Array, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw if yourJwkPublicKey is missing', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
            })
            .encrypt(plaintext, null as unknown as any),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw if yourJwkPublicKey is not a plain object', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
            })
            .encrypt(plaintext, [] as any),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw if yourJwkPublicKey.crv is missing', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const invalidJwkPublicKey = {
          kty: 'EC',
          x: 'SGVsbG8',
          y: 'SGVsbG8',
          // crv is missing
        } as any;
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
            })
            .encrypt(plaintext, invalidJwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });
    });

    describe('header validation', () => {
      it('should throw JweInvalid when no header is set', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes).encrypt(plaintext, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw JweInvalid when protected header is empty', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({})
            .encrypt(plaintext, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });
    });

    describe('crit parameter validation', () => {
      it('should work correctly when protectedHeader.crit is properly configured', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        const jwe = await new FlattenedEncrypter(aes)
          .protectedHeader({
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            crit: ['kid'],
            kid: 'test-key-id',
          })
          .encrypt(plaintext, jwkPublicKey, {
            crit: { kid: false },
          });
        expect(jwe.protected).toBeDefined();
        const decodedHeader = JSON.parse(atob(jwe.protected));
        expect(decodedHeader).toMatchObject({
          alg: 'ECDH-ES',
          enc: 'A256GCM',
          crit: ['kid'],
          kid: 'test-key-id',
        });
      });

      it('should throw JweInvalid when options.crit is not specified', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
              enc: 'A256GCM',
              crit: ['hoge'],
              hoge: 'hoge',
            })
            .encrypt(plaintext, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should work correctly when options.crit contains existent parameter', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        const jwe = await new FlattenedEncrypter(aes)
          .protectedHeader({
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            crit: ['hoge'],
            hoge: 'hoge',
          })
          .encrypt(plaintext, jwkPublicKey, {
            crit: { hoge: true },
          });
        expect(jwe.protected).toBeDefined();
        const decodedHeader = JSON.parse(atob(jwe.protected));
        expect(decodedHeader).toMatchObject({
          alg: 'ECDH-ES',
          enc: 'A256GCM',
          crit: ['hoge'],
          hoge: 'hoge',
        });
      });
    });

    describe('required header parameters', () => {
      it('should throw JweInvalid when alg is missing', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              enc: 'A256GCM',
            })
            .encrypt(plaintext, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw JweInvalid when enc is missing', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const jwkPublicKey = curve.toJwkPublicKey(
          curve.getPublicKey(rawPrivateKey, false),
        );
        await expect(
          new FlattenedEncrypter(aes)
            .protectedHeader({
              alg: 'ECDH-ES',
            })
            .encrypt(plaintext, jwkPublicKey),
        ).rejects.toThrow(JweInvalid);
      });
    });
  });

  describe('duplicate method call validation', () => {
    it('should throw JweInvalid when keyManagementParameters is called twice', () => {
      expect(() => {
        new FlattenedEncrypter(aes)
          .keyManagementParameters({ apu: new Uint8Array([1]) })
          .keyManagementParameters({ apu: new Uint8Array([2]) });
      }).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when protectedHeader is called twice', () => {
      expect(() => {
        new FlattenedEncrypter(aes)
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' });
      }).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when sharedUnprotectedHeader is called twice', () => {
      expect(() => {
        new FlattenedEncrypter(aes)
          .sharedUnprotectedHeader({ cty: 'application/json' })
          .sharedUnprotectedHeader({ cty: 'text/plain' });
      }).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when unprotectedHeader is called twice', () => {
      expect(() => {
        new FlattenedEncrypter(aes)
          .unprotectedHeader({ kid: 'key-1' })
          .unprotectedHeader({ kid: 'key-2' });
      }).toThrow(JweInvalid);
    });
  });

  describe('additionalAuthenticatedData', () => {
    it('should set AAD and return this for chaining', () => {
      const aad = new TextEncoder().encode('test-aad');
      const result = new FlattenedEncrypter(aes).additionalAuthenticatedData(
        aad,
      );
      expect(result).toBeInstanceOf(FlattenedEncrypter);
    });
  });

  describe('JWE object contents', () => {
    it('should include aad in JWE when it exists', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );
      const aad = new TextEncoder().encode('test-aad');
      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(aad)
        .encrypt(plaintext, jwkPublicKey);
      expect(jwe.aad).toBe(encodeBase64Url(aad));
    });

    it('should include unprotected and shared unprotected headers in JWE when they exist', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );
      const unprotectedHeader = { kid: 'unprotected-key-id' };
      const sharedUnprotectedHeader = { cty: 'application/json' };
      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader(unprotectedHeader)
        .sharedUnprotectedHeader(sharedUnprotectedHeader)
        .encrypt(plaintext, jwkPublicKey);
      expect(jwe.header).toEqual(unprotectedHeader);
      expect(jwe.unprotected).toEqual(sharedUnprotectedHeader);
    });

    it('should include iv and tag in JWE', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );
      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({
          alg: 'ECDH-ES',
          enc: 'A256GCM',
        })
        .encrypt(plaintext, jwkPublicKey);
      expect(jwe.iv).toBeDefined();
      expect(jwe.tag).toBeDefined();
    });

    it('should include protected header in JWE', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );
      const protectedHeader: JweHeaderParameters = {
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      };
      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader(protectedHeader)
        .encrypt(plaintext, jwkPublicKey);
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
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );

      const encrypter = new FlattenedEncrypter(aes).protectedHeader({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });

      const parameters = { kid: 'test-key', cty: 'text/plain' };
      encrypter.updateProtectedHeader(parameters);

      const jwe = await encrypter.encrypt(plaintext, jwkPublicKey);
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
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );

      const encrypter = new FlattenedEncrypter(aes);

      const parameters = { alg: 'ECDH-ES' as const, enc: 'A256GCM' as const };
      encrypter.updateProtectedHeader(parameters);

      const jwe = await encrypter.encrypt(plaintext, jwkPublicKey);
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
      const rawPrivateKey = curve.randomPrivateKey();
      const jwkPublicKey = curve.toJwkPublicKey(
        curve.getPublicKey(rawPrivateKey, false),
      );

      const encrypter = new FlattenedEncrypter(aes).protectedHeader({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });

      encrypter.updateProtectedHeader(undefined);

      const jwe = await encrypter.encrypt(plaintext, jwkPublicKey);
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
