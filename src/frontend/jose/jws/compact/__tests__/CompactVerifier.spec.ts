import { describe, expect, it } from 'vitest';
import { CompactVerifier } from '../CompactVerifier';
import { CompactSigner } from '../CompactSigner';
import { JwsInvalid, JwsSignatureVerificationFailed } from '@/jose/errors';
import { createSignatureCurve } from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';
import { JwsAlg } from '@/jose/jws/types';

describe('CompactVerifier', () => {
  describe('verification of CompactSigner output', () => {
    const curves = [
      { name: 'P-256', alg: 'ES256' as JwsAlg },
      { name: 'P-384', alg: 'ES384' as JwsAlg },
      { name: 'P-521', alg: 'ES512' as JwsAlg },
      { name: 'Ed25519', alg: 'EdDSA' as JwsAlg },
    ];

    it.each(curves)(
      'should verify JWS created by CompactSigner with $alg algorithm',
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

        // Verify with CompactVerifier
        const result = await new CompactVerifier(randomBytes).verify(
          compactJws,
          publicKey,
        );

        expect(result.payload).toEqual(payload);
        expect(result.protectedHeader).toEqual({ alg });
      },
    );
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
          new CompactVerifier(randomBytes).verify(undefined as any, publicKey),
        ).rejects.toThrow(new JwsInvalid('Compact JWS is missing'));
      });

      it('should throw error for non-string JWS', async () => {
        const publicKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new CompactVerifier(randomBytes).verify({} as any, publicKey),
        ).rejects.toThrow(new JwsInvalid('Compact JWS must be a string'));
      });

      it('should throw error for JWS with wrong number of parts', async () => {
        const publicKey = {
          kty: 'EC',
          crv: 'P-256',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new CompactVerifier(randomBytes).verify('header.payload', publicKey),
        ).rejects.toThrow(new JwsInvalid('Compact JWS must have 3 parts'));
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

        // Sign with CompactSigner
        const compactJws = await new CompactSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .sign(payload, privateKey);

        await expect(
          new CompactVerifier(randomBytes).verify(compactJws, undefined as any),
        ).rejects.toThrow(new JwsInvalid('jwkPublicKey is missing'));
      });
    });
  });

  describe('delegation to FlattenedVerifier', () => {
    it('should delegate signature verification to FlattenedVerifier', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      const signatureCurve = createSignatureCurve('P-256', randomBytes);

      const rawPrivateKey1 = signatureCurve.randomPrivateKey();
      const privateKey1 = signatureCurve.toJwkPrivateKey(rawPrivateKey1);
      const rawPrivateKey2 = signatureCurve.randomPrivateKey();
      const rawPublicKey2 = signatureCurve.getPublicKey(rawPrivateKey2);
      const publicKey2 = signatureCurve.toJwkPublicKey(rawPublicKey2);

      // Sign with first key pair
      const compactJws = await new CompactSigner(randomBytes)
        .protectedHeader({ alg: 'ES256' })
        .sign(payload, privateKey1);

      // Try to verify with different public key - should delegate to FlattenedVerifier
      await expect(
        new CompactVerifier(randomBytes).verify(compactJws, publicKey2),
      ).rejects.toThrow(new JwsSignatureVerificationFailed());
    });
  });
});
