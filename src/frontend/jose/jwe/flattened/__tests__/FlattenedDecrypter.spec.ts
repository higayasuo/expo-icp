import { describe, it, expect } from 'vitest';
import { FlattenedEncrypter } from '../FlattenedEncrypter';
import { FlattenedDecrypter } from '../FlattenedDecrypter';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createEcdhCurve } from 'noble-curves-extended';
import { JweInvalid } from '@/jose/errors/errors';
import { FlattenedJwe } from '../types';
import { parseJweProtected } from '../utils/parseJweProtected';
import { encodeBase64UrlHeader } from '@/jose/utils/encodeBase64UrlHeader';

const { getRandomBytes } = webCryptoModule;
const p256 = createEcdhCurve('P-256', getRandomBytes);
const x25519 = createEcdhCurve('X25519', getRandomBytes);
const curves = [
  { curve: p256, curveName: p256.curveName as string },
  { curve: x25519, curveName: x25519.curveName as string },
];
const aes = new WebAesCipher(getRandomBytes);

describe('FlattenedDecrypter', () => {
  describe('encrypt and decrypt', () => {
    it.each(curves)(
      'should encrypt and decrypt with ECDH-ES and A256GCM using $curveName',
      async ({ curve }) => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = curve.randomPrivateKey();
        const rawPublicKey = curve.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

        const jwe = await new FlattenedEncrypter(aes)
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .encrypt(plaintext, jwkPublicKey);

        const result = await new FlattenedDecrypter(aes).decrypt(
          jwe,
          jwkPrivateKey,
        );
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
        const jwe = await new FlattenedEncrypter(aes)
          .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
          .keyManagementParameters({ apu, apv })
          .encrypt(plaintext, jwkPublicKey);

        // Decrypt
        const decrypted = await new FlattenedDecrypter(aes).decrypt(
          jwe,
          jwkPrivateKey,
        );

        // Verify
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          'Hello, World!',
        );
      },
    );
  });

  describe('constructor', () => {
    it('should create a new instance', () => {
      expect(new FlattenedDecrypter(aes)).toBeInstanceOf(FlattenedDecrypter);
    });
  });

  describe('decrypt validations', () => {
    describe('input parameter validation', () => {
      it('should throw JweInvalid when jwe is missing', async () => {
        const rawPrivateKey = p256.randomPrivateKey();
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        await expect(
          new FlattenedDecrypter(aes).decrypt(null as any, jwkPrivateKey),
        ).rejects.toThrow(new JweInvalid('Flattened JWE is missing'));
      });

      it('should throw JweInvalid when jwe is not a plain object', async () => {
        const jwe = 'not a plain object';
        const rawPrivateKey = p256.randomPrivateKey();
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        await expect(
          new FlattenedDecrypter(aes).decrypt(jwe as any, jwkPrivateKey),
        ).rejects.toThrow(
          new JweInvalid('Flattened JWE must be a plain object'),
        );
      });

      it('should throw JweInvalid when myJwkPrivateKey is missing', async () => {
        const jwe = {
          ciphertext: 'ciphertext',
          iv: 'iv',
          tag: 'tag',
          protected: 'protected',
        } as FlattenedJwe;
        await expect(
          new FlattenedDecrypter(aes).decrypt(jwe, null as any),
        ).rejects.toThrow(new JweInvalid('myJwkPrivateKey is missing'));
      });

      it('should throw JweInvalid when myJwkPrivateKey is not a plain object', async () => {
        const jwe = {
          ciphertext: 'ciphertext',
          iv: 'iv',
          tag: 'tag',
          protected: 'protected',
        } as FlattenedJwe;
        await expect(
          new FlattenedDecrypter(aes).decrypt(jwe, [] as any),
        ).rejects.toThrow(
          new JweInvalid('myJwkPrivateKey must be a plain object'),
        );
      });

      it('should throw JweInvalid when myJwkPrivateKey.crv is missing', async () => {
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
          new FlattenedDecrypter(aes).decrypt(jwe, invalidJwkPrivateKey),
        ).rejects.toThrow(new JweInvalid('myJwkPrivateKey.crv is missing'));
      });
    });

    describe('crit parameter validation', () => {
      it('should work correctly when options.crit contains existent parameter', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = p256.randomPrivateKey();
        const rawPublicKey = p256.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

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
        const decrypted = await new FlattenedDecrypter(aes).decrypt(
          jwe,
          jwkPrivateKey,
          {
            crit: { hoge: true },
          },
        );
        expect(new TextDecoder().decode(decrypted.plaintext)).toBe(
          'Hello, World!',
        );
      });

      it('should throw JweInvalid when options.crit is not specified', async () => {
        const plaintext = new TextEncoder().encode('Hello, World!');
        const rawPrivateKey = p256.randomPrivateKey();
        const rawPublicKey = p256.getPublicKey(rawPrivateKey);
        const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
        const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

        // Create a valid JWE
        const jwe = await new FlattenedEncrypter(aes)
          .protectedHeader({
            alg: 'ECDH-ES',
            enc: 'A256GCM',
            crit: ['hoge'],
            hoge: 'hoge',
          })
          .encrypt(plaintext, jwkPublicKey, { crit: { hoge: true } });

        // Test with crit option containing non-existent parameter
        await expect(
          new FlattenedDecrypter(aes).decrypt(jwe, jwkPrivateKey),
        ).rejects.toThrow(JweInvalid);
      });
    });

    describe('JWE field validations', () => {
      describe('protected field', () => {
        it('should throw JweInvalid when protected header is missing', async () => {
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await new FlattenedEncrypter(aes)
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the protected field to make it invalid
          const { protected: _, ...invalidJwe } = validJwe;

          await expect(
            new FlattenedDecrypter(aes).decrypt(
              invalidJwe as FlattenedJwe,
              jwkPrivateKey,
            ),
          ).rejects.toThrow(new JweInvalid('Failed to decrypt JWE'));
        });

        describe('alg parameter', () => {
          it('should throw JweInvalid when alg is missing', async () => {
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await new FlattenedEncrypter(aes)
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            const parsedProtected = parseJweProtected(validJwe.protected);
            delete parsedProtected.alg;

            const invalidJwe = {
              ...validJwe,
              protected: encodeBase64UrlHeader(parsedProtected),
            };

            await expect(
              new FlattenedDecrypter(aes).decrypt(invalidJwe, jwkPrivateKey),
            ).rejects.toThrow(JweInvalid);
          });

          it('should throw JweInvalid when alg is not in keyManagementAlgorithms', async () => {
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await new FlattenedEncrypter(aes)
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            // Test with restricted keyManagementAlgorithms that don't include ECDH-ES
            await expect(
              new FlattenedDecrypter(aes).decrypt(validJwe, jwkPrivateKey, {
                keyManagementAlgorithms: ['RSA-OAEP'],
              }),
            ).rejects.toThrow(JweInvalid);
          });
        });

        describe('enc parameter', () => {
          it('should throw JweInvalid when enc is missing', async () => {
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await new FlattenedEncrypter(aes)
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            const parsedProtected = parseJweProtected(validJwe.protected);
            delete parsedProtected.enc;

            const invalidJwe = {
              ...validJwe,
              protected: encodeBase64UrlHeader(parsedProtected),
            };

            await expect(
              new FlattenedDecrypter(aes).decrypt(invalidJwe, jwkPrivateKey),
            ).rejects.toThrow(JweInvalid);
          });

          it('should throw JweInvalid when enc is not in contentEncryptionAlgorithms', async () => {
            const plaintext = new TextEncoder().encode('Hello, World!');
            const rawPrivateKey = p256.randomPrivateKey();
            const rawPublicKey = p256.getPublicKey(rawPrivateKey);
            const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
            const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

            // Create a valid JWE first
            const validJwe = await new FlattenedEncrypter(aes)
              .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
              .encrypt(plaintext, jwkPublicKey);

            // Test with restricted contentEncryptionAlgorithms that don't include A256GCM
            await expect(
              new FlattenedDecrypter(aes).decrypt(validJwe, jwkPrivateKey, {
                contentEncryptionAlgorithms: ['A128CBC-HS256'],
              }),
            ).rejects.toThrow(JweInvalid);
          });
        });
      });

      describe('ciphertext field', () => {
        it('should throw JweInvalid when ciphertext is missing', async () => {
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await new FlattenedEncrypter(aes)
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the ciphertext field to make it invalid
          const { ciphertext: _, ...invalidJwe } = validJwe;

          await expect(
            new FlattenedDecrypter(aes).decrypt(
              invalidJwe as FlattenedJwe,
              jwkPrivateKey,
            ),
          ).rejects.toThrow(new JweInvalid('Failed to decrypt JWE'));
        });
      });

      describe('iv field', () => {
        it('should throw JweInvalid when iv is missing', async () => {
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await new FlattenedEncrypter(aes)
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the iv field to make it invalid
          const { iv: _, ...invalidJwe } = validJwe;

          await expect(
            new FlattenedDecrypter(aes).decrypt(
              invalidJwe as FlattenedJwe,
              jwkPrivateKey,
            ),
          ).rejects.toThrow(new JweInvalid('Failed to decrypt JWE'));
        });
      });

      describe('tag field', () => {
        it('should throw JweInvalid when tag is missing', async () => {
          const plaintext = new TextEncoder().encode('Hello, World!');
          const rawPrivateKey = p256.randomPrivateKey();
          const rawPublicKey = p256.getPublicKey(rawPrivateKey);
          const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
          const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);

          // Create a valid JWE first
          const validJwe = await new FlattenedEncrypter(aes)
            .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
            .encrypt(plaintext, jwkPublicKey);

          // Remove the tag field to make it invalid
          const { tag: _, ...invalidJwe } = validJwe;

          await expect(
            new FlattenedDecrypter(aes).decrypt(
              invalidJwe as FlattenedJwe,
              jwkPrivateKey,
            ),
          ).rejects.toThrow(new JweInvalid('Failed to decrypt JWE'));
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

      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .additionalAuthenticatedData(aad)
        .encrypt(plaintext, jwkPublicKey);

      const decrypted = await new FlattenedDecrypter(aes).decrypt(
        jwe,
        jwkPrivateKey,
      );

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

      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .sharedUnprotectedHeader(sharedUnprotectedHeader)
        .encrypt(plaintext, jwkPublicKey);

      const decrypted = await new FlattenedDecrypter(aes).decrypt(
        jwe,
        jwkPrivateKey,
      );

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

      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .unprotectedHeader(unprotectedHeader)
        .encrypt(plaintext, jwkPublicKey);

      const decrypted = await new FlattenedDecrypter(aes).decrypt(
        jwe,
        jwkPrivateKey,
      );

      expect(decrypted.unprotectedHeader).toEqual(unprotectedHeader);
    });

    it('should include protectedHeader in result', async () => {
      const rawPrivateKey = p256.randomPrivateKey();
      const rawPublicKey = p256.getPublicKey(rawPrivateKey);
      const jwkPrivateKey = p256.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = p256.toJwkPublicKey(rawPublicKey);
      const plaintext = new TextEncoder().encode('Hello, World!');

      const jwe = await new FlattenedEncrypter(aes)
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, jwkPublicKey);

      const result = await new FlattenedDecrypter(aes).decrypt(
        jwe,
        jwkPrivateKey,
      );
      expect(result.protectedHeader).toMatchObject({
        alg: 'ECDH-ES',
        enc: 'A256GCM',
      });
    });
  });
});
