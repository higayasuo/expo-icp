import { describe, expect, it } from 'vitest';
import { FlattenedVerifier } from '../FlattenedVerifier';
import { FlattenedSigner } from '../FlattenedSigner';
import { JwsInvalid, JwsSignatureVerificationFailed } from '@/jose/errors';
import { createSignatureCurve } from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';
import { JwsAlg } from '../../types';
import { JwsHeaderParameters } from '../../types';

describe('FlattenedVerifier', () => {
  describe('signing and verification', () => {
    const curves = [
      { name: 'P-256', alg: 'ES256' as JwsAlg },
      { name: 'P-384', alg: 'ES384' as JwsAlg },
      { name: 'P-521', alg: 'ES512' as JwsAlg },
      { name: 'Ed25519', alg: 'EdDSA' as JwsAlg },
    ];

    it.each(curves)(
      'should verify JWS signed with $alg algorithm',
      async ({ name, alg }) => {
        const payload = Uint8Array.from(
          new TextEncoder().encode(`Test payload for ${alg}`),
        );

        // Generate key pair for this test
        const signatureCurve = createSignatureCurve(name, randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
        const publicKey = signatureCurve.toJwkPublicKey(
          signatureCurve.getPublicKey(rawPrivateKey),
        );

        // Sign with FlattenedSigner
        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg })
          .sign(payload, privateKey);

        // Verify with FlattenedVerifier
        const result = await new FlattenedVerifier(randomBytes).verify(
          jws,
          publicKey,
        );

        expect(result.payload).toEqual(payload);
        expect(result.protectedHeader).toEqual({ alg });
      },
    );
  });

  describe('b64 parameter handling', () => {
    it('should verify JWS with b64: true (default)', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign with b64: true
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
          b64: true,
          crit: ['b64'],
        })
        .sign(payload, privateKey);

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        jws,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({
        alg: 'ES256',
        b64: true,
        crit: ['b64'],
      });
    });

    it('should verify JWS with b64: false', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign with b64: false
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
          b64: false,
          crit: ['b64'],
        })
        .sign(payload, privateKey);

      // For b64: false, we need to provide the payload separately
      const jwsWithPayload = { ...jws, payload };

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        jwsWithPayload,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({
        alg: 'ES256',
        b64: false,
        crit: ['b64'],
      });
    });
  });

  describe('unprotected headers', () => {
    it('should verify JWS with unprotected headers', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      const unprotectedHeader = {
        kid: 'test-key-id',
        x5t: 'test-thumbprint',
      };

      // Sign with unprotected header
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
        })
        .unprotectedHeader(unprotectedHeader)
        .sign(payload, privateKey);

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        jws,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({ alg: 'ES256' });
      expect(result.unprotectedHeader).toEqual(unprotectedHeader);
    });
  });

  describe('parameter validation', () => {
    describe('JWS validation', () => {
      it('should throw error for missing JWS', async () => {
        const publicKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedVerifier(randomBytes).verify(
            undefined as any,
            publicKey,
          ),
        ).rejects.toThrow(new JwsInvalid('Flattened JWS is missing'));
      });

      it('should throw error for null JWS', async () => {
        const publicKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedVerifier(randomBytes).verify(null as any, publicKey),
        ).rejects.toThrow(new JwsInvalid('Flattened JWS is missing'));
      });

      it('should throw error for non-object JWS', async () => {
        const publicKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedVerifier(randomBytes).verify(
            'not an object' as any,
            publicKey,
          ),
        ).rejects.toThrow(
          new JwsInvalid('Flattened JWS must be a plain object'),
        );
      });

      it('should throw error for array JWS', async () => {
        const publicKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedVerifier(randomBytes).verify([] as any, publicKey),
        ).rejects.toThrow(
          new JwsInvalid('Flattened JWS must be a plain object'),
        );
      });
    });

    describe('JWK validation', () => {
      it('should throw error for missing JWK', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        // Sign with FlattenedSigner
        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, privateKey);

        await expect(
          new FlattenedVerifier(randomBytes).verify(jws, undefined as any),
        ).rejects.toThrow(new JwsInvalid('jwkPublicKey is missing'));
      });

      it('should throw error for null JWK', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        // Sign with FlattenedSigner
        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, privateKey);

        await expect(
          new FlattenedVerifier(randomBytes).verify(jws, null as any),
        ).rejects.toThrow(new JwsInvalid('jwkPublicKey is missing'));
      });

      it('should throw error for non-object JWK', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        // Sign with FlattenedSigner
        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, privateKey);

        await expect(
          new FlattenedVerifier(randomBytes).verify(
            jws,
            'not an object' as any,
          ),
        ).rejects.toThrow(
          new JwsInvalid('jwkPublicKey must be a plain object'),
        );
      });

      it('should throw error for array JWK', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        // Sign with FlattenedSigner
        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, privateKey);

        await expect(
          new FlattenedVerifier(randomBytes).verify(jws, [] as any),
        ).rejects.toThrow(
          new JwsInvalid('jwkPublicKey must be a plain object'),
        );
      });

      it('should throw error for missing crv in JWK', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        // Sign with FlattenedSigner
        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, privateKey);

        const invalidPublicKey = {
          kty: 'EC',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedVerifier(randomBytes).verify(
            jws,
            invalidPublicKey as any,
          ),
        ).rejects.toThrow(new JwsInvalid('jwkPublicKey.crv is missing'));
      });
    });
  });

  describe('signature verification', () => {
    it('should throw error for invalid signature', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign with FlattenedSigner
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Tamper with the signature
      const tamperedJws = { ...jws, signature: 'tampered_signature' };

      await expect(
        new FlattenedVerifier(randomBytes).verify(tamperedJws, publicKey),
      ).rejects.toThrow(new JwsSignatureVerificationFailed());
    });

    it('should throw error for wrong public key', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      const signatureCurve = createSignatureCurve('P-256', randomBytes);

      const rawPrivateKey1 = signatureCurve.randomPrivateKey();
      const privateKey1 = signatureCurve.toJwkPrivateKey(rawPrivateKey1);
      const rawPrivateKey2 = signatureCurve.randomPrivateKey();
      const rawPublicKey2 = signatureCurve.getPublicKey(rawPrivateKey2);
      const publicKey2 = signatureCurve.toJwkPublicKey(rawPublicKey2);

      // Sign with first key pair
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey1);

      // Try to verify with different public key
      await expect(
        new FlattenedVerifier(randomBytes).verify(jws, publicKey2),
      ).rejects.toThrow(new JwsSignatureVerificationFailed());
    });
  });

  describe('critical parameters handling', () => {
    it('should handle custom critical parameters', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
          b64: true,
          crit: ['b64', 'custom-param'],
        })
        .unprotectedHeader({
          'custom-param': 'custom-value',
        })
        .sign(payload, privateKey, {
          crit: { 'custom-param': false },
        });

      // Verify with custom critical parameter handling
      const result = await new FlattenedVerifier(randomBytes).verify(
        jws,
        publicKey,
        {
          crit: { 'custom-param': false },
        },
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({
        alg: 'ES256',
        b64: true,
        crit: ['b64', 'custom-param'],
      });
      expect(result.unprotectedHeader).toEqual({
        'custom-param': 'custom-value',
      });
    });
  });

  describe('header validation', () => {
    it('should throw error when protected header is missing', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign without protected header
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Should throw error when trying to verify without protected header
      const invalidJws = { ...jws, protected: undefined } as any;
      await expect(
        new FlattenedVerifier(randomBytes).verify(invalidJws, publicKey),
      ).rejects.toThrow(new JwsInvalid('Failed to verify JWS signature'));
    });
  });

  describe('edge cases', () => {
    it('should handle empty payload', async () => {
      const payload = new Uint8Array([]);

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign with FlattenedSigner
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        jws,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({ alg: 'ES256' });
    });

    it('should handle large payload', async () => {
      const payload = randomBytes(1024);

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign with FlattenedSigner
      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        jws,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({ alg: 'ES256' });
    });
  });
});
