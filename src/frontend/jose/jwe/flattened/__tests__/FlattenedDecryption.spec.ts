import { describe, it, expect } from 'vitest';
import { FlattenedEncryption } from '../FlattenedEncryption';
import { FlattenedDecryption } from '../FlattenedDecryption';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createEcdhCurve } from 'noble-curves-extended';
import { JweInvalid } from '@/jose/errors/errors';
import { FlattenedJwe } from '../../types';
import { parseJweProtected } from '../utils/parseJweProtected';
import { buildBase64UrlJweHeader } from '../utils/buildBase64UrlJweHeader';

const { getRandomBytes } = webCryptoModule;
const p256 = createEcdhCurve('P-256', getRandomBytes);
const x25519 = createEcdhCurve('X25519', getRandomBytes);
const curves = [
  { curve: p256, curveName: p256.curveName as string },
  { curve: x25519, curveName: x25519.curveName as string },
];
const aes = new WebAesCipher(getRandomBytes);

describe('FlattenedDecryption', () => {
  describe('encrypt and decrypt', () => {
    it.each(curves)(
      'should encrypt and decrypt with ECDH-ES and A256GCM using $curveName',
      async ({ curve }) => {
        const decryption = new FlattenedDecryption(aes);
        const encryption = new FlattenedEncryption(aes);
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const rawPublicKey = curve.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

        const jwe = await encryption
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .encrypt(plaintext, jwkPublicKey);

        const result = await decryption.decrypt(jwe, jwkPrivateKey);
        expect(new TextDecoder().decode(result.plaintext)).toBe(
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

        // Create plaintext
        const plaintext = new TextEncoder().encode('Hello, World!');

        // Create apu/apv
        const apu = new TextEncoder().encode('Alice');
        const apv = new TextEncoder().encode('Bob');

        // Encrypt
        const encryption = new FlattenedEncryption(aes)
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .keyManagementParameters({ apu, apv });

        const jwe = await encryption.encrypt(plaintext, jwkPublicKey);

        // Decrypt
        const decryption = new FlattenedDecryption(aes);
        const decrypted = await decryption.decrypt(jwe, jwkPrivateKey);

        // Verify
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          'Hello, World!',
        );
      },
    );
  });

  describe('constructor', () => {
    it('should create a new instance', () => {
      const decryption = new FlattenedDecryption(aes);
      expect(decryption).toBeInstanceOf(FlattenedDecryption);
    });
  });

  describe('decrypt validations', () => {
    describe('input parameter validation', () => {
      it('should throw JweInvalid when jwe is missing', async () => {
        const decryption = new FlattenedDecryption(aes);
        const rawPrivateKey = p256.randomPrivateKey();
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        await expect(
          decryption.decrypt(null as any, jwkPrivateKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw JweInvalid when jwe is not a plain object', async () => {
        const decryption = new FlattenedDecryption(aes);
        const jwe = 'not a plain object';
        const rawPrivateKey = p256.randomPrivateKey();
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        await expect(
          decryption.decrypt(jwe as any, jwkPrivateKey),
        ).rejects.toThrow(JweInvalid);
      });

      it('should throw JweInvalid when myJwkPrivateKey is missing', async () => {
        const decryption = new FlattenedDecryption(aes);
        const jwe = {
          ciphertext: 'ciphertext',
          iv: 'iv',
          tag: 'tag',
          protected: 'protected',
        } as FlattenedJwe;
        await expect(decryption.decrypt(jwe, null as any)).rejects.toThrow(
          JweInvalid,
        );
      });

      it('should throw JweInvalid when myJwkPrivateKey is not a plain object', async () => {
        const decryption = new FlattenedDecryption(aes);
        const jwe = {
          ciphertext: 'ciphertext',
          iv: 'iv',
          tag: 'tag',
          protected: 'protected',
        } as FlattenedJwe;
        await expect(decryption.decrypt(jwe, [] as any)).rejects.toThrow(
          JweInvalid,
        );
      });

      it('should throw JweInvalid when myJwkPrivateKey.crv is missing', async () => {
        const decryption = new FlattenedDecryption(aes);
        const jwe = {
          ciphertext: 'ciphertext',
          iv: 'iv',
          tag: 'tag',
          protected: 'protected',
        } as FlattenedJwe;
        const invalidJwkPrivateKey = {
          kty: 'EC',
          d: 'SGVsbG8',
          x: 'SGVsbG8',
          y: 'SGVsbG8',
          // crv is missing
        } as any;
        await expect(
          decryption.decrypt(jwe, invalidJwkPrivateKey),
        ).rejects.toThrow(JweInvalid);
      });
    });

    describe('crit parameter validation', () => {
      it('should work correctly when options.crit contains existent parameter', async () => {
        const decryption = new FlattenedDecryption(aes);
        const encryption = new FlattenedEncryption(aes);
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = p256.randomPrivateKey();
        const rawPublicKey = p256.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

        const jwe = await encryption
          .protectedHeader({
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            crit: ['hoge'],
            hoge: 'hoge',
          })
          .encrypt(plaintext, jwkPublicKey, {
            crit: { hoge: true },
          });
        const decrypted = await decryption.decrypt(jwe, jwkPrivateKey, {
          crit: { hoge: true },
        });
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          'Hello, World!',
        );
      });

      it('should throw JweInvalid when options.crit is not specified', async () => {
        const decryption = new FlattenedDecryption(aes);
        const encryption = new FlattenedEncryption(aes);
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = p256.randomPrivateKey();
        const rawPublicKey = p256.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

        // Create a valid JWE
        const jwe = await encryption
          .protectedHeader({
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            crit: ['hoge'],
            hoge: 'hoge',
          })
          .encrypt(plaintext, jwkPublicKey, { crit: { hoge: true } });

        // Test with crit option containing non-existent parameter
        await expect(decryption.decrypt(jwe, jwkPrivateKey)).rejects.toThrow(
          JweInvalid,
        );
      });
    });

    describe('JWE field validations', () => {
      describe('protected field', () => {
        it('should throw JweInvalid when protected header is missing', async () => {
          const decryption = new FlattenedDecryption(aes);
          const encryption = new FlattenedEncryption(aes);
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await encryption
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the protected field to make it invalid
          const { protected: _, ...invalidJwe } = validJwe;

          await expect(
            decryption.decrypt(invalidJwe as FlattenedJwe, jwkPrivateKey),
          ).rejects.toThrow(JweInvalid);
        });

        describe('alg parameter', () => {
          it('should throw JweInvalid when alg is missing', async () => {
            const decryption = new FlattenedDecryption(aes);
            const encryption = new FlattenedEncryption(aes);
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await encryption
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            const parsedProtected = parseJweProtected(validJwe.protected);
            delete parsedProtected.alg;

            const invalidJwe = {
              ...validJwe,
              protected: buildBase64UrlJweHeader(parsedProtected),
            };

            await expect(
              decryption.decrypt(invalidJwe, jwkPrivateKey),
            ).rejects.toThrow(JweInvalid);
          });

          it('should throw JweInvalid when alg is not in keyManagementAlgorithms', async () => {
            const decryption = new FlattenedDecryption(aes);
            const encryption = new FlattenedEncryption(aes);
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await encryption
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            // Test with restricted keyManagementAlgorithms that don't include ECDH-ES
            await expect(
              decryption.decrypt(validJwe, jwkPrivateKey, {
                keyManagementAlgorithms: ['RSA-OAEP'],
              }),
            ).rejects.toThrow(JweInvalid);
          });
        });

        describe('enc parameter', () => {
          it('should throw JweInvalid when enc is missing', async () => {
            const decryption = new FlattenedDecryption(aes);
            const encryption = new FlattenedEncryption(aes);
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await encryption
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            const parsedProtected = parseJweProtected(validJwe.protected);
            delete parsedProtected.enc;

            const invalidJwe = {
              ...validJwe,
              protected: buildBase64UrlJweHeader(parsedProtected),
            };

            await expect(
              decryption.decrypt(invalidJwe, jwkPrivateKey),
            ).rejects.toThrow(JweInvalid);
          });

          it('should throw JweInvalid when enc is not in contentEncryptionAlgorithms', async () => {
            const decryption = new FlattenedDecryption(aes);
            const encryption = new FlattenedEncryption(aes);
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await encryption
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            // Test with restricted contentEncryptionAlgorithms that don't include A256GCM
            await expect(
              decryption.decrypt(validJwe, jwkPrivateKey, {
                contentEncryptionAlgorithms: ['A128CBC-HS256'],
              }),
            ).rejects.toThrow(JweInvalid);
          });
        });
      });

      describe('ciphertext field', () => {
        it('should throw JweInvalid when ciphertext is missing', async () => {
          const decryption = new FlattenedDecryption(aes);
          const encryption = new FlattenedEncryption(aes);
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await encryption
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the ciphertext field to make it invalid
          const { ciphertext: _, ...invalidJwe } = validJwe;

          await expect(
            decryption.decrypt(invalidJwe as FlattenedJwe, jwkPrivateKey),
          ).rejects.toThrow(JweInvalid);
        });
      });

      describe('iv field', () => {
        it('should throw JweInvalid when iv is missing', async () => {
          const decryption = new FlattenedDecryption(aes);
          const encryption = new FlattenedEncryption(aes);
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await encryption
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the iv field to make it invalid
          const { iv: _, ...invalidJwe } = validJwe;

          await expect(
            decryption.decrypt(invalidJwe as FlattenedJwe, jwkPrivateKey),
          ).rejects.toThrow(JweInvalid);
        });
      });

      describe('tag field', () => {
        it('should throw JweInvalid when tag is missing', async () => {
          const decryption = new FlattenedDecryption(aes);
          const encryption = new FlattenedEncryption(aes);
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await encryption
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the tag field to make it invalid
          const { tag: _, ...invalidJwe } = validJwe;

          await expect(
            decryption.decrypt(invalidJwe as FlattenedJwe, jwkPrivateKey),
          ).rejects.toThrow(JweInvalid);
        });
      });
    });
  });

  describe('decrypt results', () => {
    it('should include aad in decrypted result when it exists', async () => {
      const rawPrivateKey = p256.randomPrivateKey();
      const rawPublicKey = p256.getPublicKey(rawPrivateKey);
      const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const aad = new TextEncoder().encode('test-aad');

      const encryption = new FlattenedEncryption(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(aad);

      const jwe = await encryption.encrypt(plaintext, jwkPublicKey);

      const decryption = new FlattenedDecryption(aes);
      const decrypted = await decryption.decrypt(jwe, jwkPrivateKey);

      expect(decrypted.additionalAuthenticatedData).toEqual(
        Uint8Array.from(aad),
      );
    });

    it('should include shared unprotected header in decrypted result when it exists', async () => {
      const rawPrivateKey = p256.randomPrivateKey();
      const rawPublicKey = p256.getPublicKey(rawPrivateKey);
      const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const sharedUnprotectedHeader = { test: 'value' };

      const encryption = new FlattenedEncryption(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .sharedUnprotectedHeader(sharedUnprotectedHeader);

      const jwe = await encryption.encrypt(plaintext, jwkPublicKey);

      const decryption = new FlattenedDecryption(aes);
      const decrypted = await decryption.decrypt(jwe, jwkPrivateKey);

      expect(decrypted.sharedUnprotectedHeader).toEqual(
        sharedUnprotectedHeader,
      );
    });

    it('should include unprotected header in decrypted result when it exists', async () => {
      const rawPrivateKey = p256.randomPrivateKey();
      const rawPublicKey = p256.getPublicKey(rawPrivateKey);
      const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const unprotectedHeader = { test: 'value' };

      const encryption = new FlattenedEncryption(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader(unprotectedHeader);

      const jwe = await encryption.encrypt(plaintext, jwkPublicKey);

      const decryption = new FlattenedDecryption(aes);
      const decrypted = await decryption.decrypt(jwe, jwkPrivateKey);

      expect(decrypted.unprotectedHeader).toEqual(unprotectedHeader);
    });

    it('should include protectedHeader in result', async () => {
      const decryption = new FlattenedDecryption(aes);
      const encryption = new FlattenedEncryption(aes);
      const rawPrivateKey = p256.randomPrivateKey();
      const rawPublicKey = p256.getPublicKey(rawPrivateKey);
      const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const jwe = await encryption
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, jwkPublicKey);

      const result = await decryption.decrypt(jwe, jwkPrivateKey);
      expect(result.protectedHeader).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
    });
  });
});
