import { describe, expect, it } from 'vitest';
import { CompactSigner } from '../CompactSigner';
import { FlattenedVerifier } from '@/jose/jws/flattened/FlattenedVerifier';
import { JwsInvalid } from '@/jose/errors';
import { createSignatureCurve } from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';
import { JwsAlg } from '@/jose/jws/types';

describe('CompactSigner', () => {
  describe('signing and verification with FlattenedVerifier', () => {
    const curves = [
      { name: 'P-256', alg: 'ES256' as JwsAlg },
      { name: 'P-384', alg: 'ES384' as JwsAlg },
      { name: 'P-521', alg: 'ES512' as JwsAlg },
      { name: 'Ed25519', alg: 'EdDSA' as JwsAlg },
    ];

    it.each(curves)(
      'should sign with $alg and verify with FlattenedVerifier',
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

        // Sign with CompactSigner
        const compactJws = await new CompactSigner(randomBytes)
          .protectedHeader({ alg })
          .sign(payload, privateKey);

        // Parse the compact JWS to get components
        const [protectedB64, payloadB64, signatureB64] = compactJws.split('.');

        // Convert to Flattened JWS format for verification
        const flattenedJws = {
          protected: protectedB64,
          payload: payloadB64,
          signature: signatureB64,
        };

        // Verify with FlattenedVerifier
        const result = await new FlattenedVerifier(randomBytes).verify(
          flattenedJws,
          publicKey,
        );

        expect(result.payload).toEqual(payload);
        expect(result.protectedHeader).toEqual({ alg });
      },
    );
  });

  describe('b64 parameter handling', () => {
    it('should sign with b64: true and verify correctly', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);
      const publicKey = signatureCurve.toJwkPublicKey(
        signatureCurve.getPublicKey(rawPrivateKey),
      );

      // Sign with b64: true
      const compactJws = await new CompactSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
          b64: true,
          crit: ['b64'],
        })
        .sign(payload, privateKey);

      // Parse and convert to Flattened JWS
      const [protectedB64, payloadB64, signatureB64] = compactJws.split('.');
      const flattenedJws = {
        protected: protectedB64,
        payload: payloadB64,
        signature: signatureB64,
      };

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        flattenedJws,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({
        alg: 'ES256',
        b64: true,
        crit: ['b64'],
      });
    });

    it('should throw error for b64: false (not supported in compact format)', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      // Sign with b64: false should throw error
      await expect(
        new CompactSigner(randomBytes)
          .protectedHeader({
            alg: 'ES256',
            b64: false,
            crit: ['b64'],
          })
          .sign(payload, privateKey),
      ).rejects.toThrow(
        new JwsInvalid(
          'use the flattened module for creating JWS with b64: false',
        ),
      );
    });
  });

  describe('compact JWS format validation', () => {
    it('should produce valid compact JWS format', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      // Sign with CompactSigner
      const compactJws = await new CompactSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Validate compact JWS format (three parts separated by dots)
      const parts = compactJws.split('.');
      expect(parts).toHaveLength(3);
      expect(parts[0]).toBeTruthy(); // protected header
      expect(parts[1]).toBeTruthy(); // payload
      expect(parts[2]).toBeTruthy(); // signature

      // All parts should be base64url encoded
      const base64UrlRegex = /^[A-Za-z0-9_-]+$/;
      expect(base64UrlRegex.test(parts[0])).toBe(true);
      expect(base64UrlRegex.test(parts[1])).toBe(true);
      expect(base64UrlRegex.test(parts[2])).toBe(true);
    });
  });

  describe('error cases', () => {
    it('should throw error for missing payload', async () => {
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(undefined as any, privateKey),
      ).rejects.toThrow(new JwsInvalid('payload is missing'));
    });

    it('should throw error for missing private key', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      await expect(
        new CompactSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, undefined as any),
      ).rejects.toThrow(new JwsInvalid('jwkPrivateKey is missing'));
    });

    it('should throw error for missing protected header', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      await expect(
        new CompactSigner(randomBytes).sign(payload, privateKey),
      ).rejects.toThrow(new JwsInvalid('Failed to sign payload'));
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

      // Sign with CompactSigner
      const compactJws = await new CompactSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Parse and convert to Flattened JWS
      const [protectedB64, payloadB64, signatureB64] = compactJws.split('.');
      const flattenedJws = {
        protected: protectedB64,
        payload: payloadB64,
        signature: signatureB64,
      };

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        flattenedJws,
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

      // Sign with CompactSigner
      const compactJws = await new CompactSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey);

      // Parse and convert to Flattened JWS
      const [protectedB64, payloadB64, signatureB64] = compactJws.split('.');
      const flattenedJws = {
        protected: protectedB64,
        payload: payloadB64,
        signature: signatureB64,
      };

      // Verify with FlattenedVerifier
      const result = await new FlattenedVerifier(randomBytes).verify(
        flattenedJws,
        publicKey,
      );

      expect(result.payload).toEqual(payload);
      expect(result.protectedHeader).toEqual({ alg: 'ES256' });
    });
  });
});
