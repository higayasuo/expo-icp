import { describe, expect, it } from 'vitest';
import { FlattenedSigner } from '../FlattenedSigner';
import { flattenedVerify } from 'jose';
import { JwsInvalid } from '@/jose/errors';
import { createSignatureCurve } from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';
import { JwsAlg } from '../../types';

describe('FlattenedSigner', () => {
  describe('signing and verification', () => {
    const curves = [
      { name: 'P-256', alg: 'ES256' as JwsAlg },
      { name: 'P-384', alg: 'ES384' as JwsAlg },
      { name: 'P-521', alg: 'ES512' as JwsAlg },
      { name: 'Ed25519', alg: 'EdDSA' as JwsAlg },
    ];

    it.each(curves)(
      'should sign and verify with $alg algorithm',
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

        const jws = await new FlattenedSigner(randomBytes)
          .protectedHeader({ alg })
          .sign(payload, privateKey);

        const verified = await flattenedVerify(jws, publicKey);
        expect(verified.payload).toEqual(payload);
        expect(verified.protectedHeader).toEqual({ alg });
      },
    );
  });

  describe('b64 parameter handling', () => {
    it('should handle b64: true (default)', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
          b64: true,
          crit: ['b64'],
        })
        .sign(payload, privateKey);

      // With b64: true, payload should be Base64URL encoded
      expect(jws.payload).toBeTruthy();
      expect(jws.payload).not.toBe('');

      const verified = await flattenedVerify(
        jws,
        signatureCurve.toJwkPublicKey(
          signatureCurve.getPublicKey(rawPrivateKey),
        ),
      );
      expect(verified.payload).toEqual(payload);
    });

    it('should handle b64: false', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
          b64: false,
          crit: ['b64'],
        })
        .sign(payload, privateKey);

      // With b64: false, payload should be empty string
      expect(jws.payload).toBe('');

      const verified = await flattenedVerify(
        { ...jws, payload },
        signatureCurve.toJwkPublicKey(
          signatureCurve.getPublicKey(rawPrivateKey),
        ),
      );
      expect(verified.payload).toEqual(payload);
    });
  });

  describe('unprotected headers', () => {
    it('should include unprotected headers in JWS', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      const unprotectedHeader = {
        kid: 'test-key-id',
        x5t: 'test-thumbprint',
      };

      const jws = await new FlattenedSigner(randomBytes)
        .protectedHeader({
          alg: 'ES256',
        })
        .unprotectedHeader(unprotectedHeader)
        .sign(payload, privateKey);

      expect(jws.header).toEqual(unprotectedHeader);

      const verified = await flattenedVerify(
        jws,
        signatureCurve.toJwkPublicKey(
          signatureCurve.getPublicKey(rawPrivateKey),
        ),
      );
      expect(verified.payload).toEqual(payload);
    });
  });

  describe('parameter validation', () => {
    describe('payload validation', () => {
      it('should throw error for missing payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(
          new FlattenedSigner(randomBytes).sign(undefined as any, privateKey),
        ).rejects.toThrow(new JwsInvalid('payload is missing'));
      });

      it('should throw error for null payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(
          new FlattenedSigner(randomBytes).sign(null as any, privateKey),
        ).rejects.toThrow(new JwsInvalid('payload is missing'));
      });

      it('should throw error for empty payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(
          new FlattenedSigner(randomBytes).sign('' as any, privateKey),
        ).rejects.toThrow(new JwsInvalid('payload must be a Uint8Array'));
      });

      it('should throw error for non-Uint8Array payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(
          new FlattenedSigner(randomBytes).sign(
            'not a Uint8Array' as any,
            privateKey,
          ),
        ).rejects.toThrow(new JwsInvalid('payload must be a Uint8Array'));
      });

      it('should throw error for array payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(
          new FlattenedSigner(randomBytes).sign([1, 2, 3] as any, privateKey),
        ).rejects.toThrow(new JwsInvalid('payload must be a Uint8Array'));
      });
    });

    describe('jwkPrivateKey validation', () => {
      it('should throw error for missing private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(
          new FlattenedSigner(randomBytes).sign(payload, undefined as any),
        ).rejects.toThrow(new JwsInvalid('jwkPrivateKey is missing'));
      });

      it('should throw error for null private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(
          new FlattenedSigner(randomBytes).sign(payload, null as any),
        ).rejects.toThrow(new JwsInvalid('jwkPrivateKey is missing'));
      });

      it('should throw error for non-object private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(
          new FlattenedSigner(randomBytes).sign(
            payload,
            'not an object' as any,
          ),
        ).rejects.toThrow(
          new JwsInvalid('jwkPrivateKey must be a plain object'),
        );
      });

      it('should throw error for array private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(
          new FlattenedSigner(randomBytes).sign(payload, [] as any),
        ).rejects.toThrow(
          new JwsInvalid('jwkPrivateKey must be a plain object'),
        );
      });

      it('should throw error for missing crv in private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );
        const invalidPrivateKey = {
          kty: 'EC',
          d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedSigner(randomBytes).sign(
            payload,
            invalidPrivateKey as any,
          ),
        ).rejects.toThrow(new JwsInvalid('jwkPrivateKey.crv is missing'));
      });

      it('should throw error for private key with null crv', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );
        const invalidPrivateKey = {
          kty: 'EC',
          crv: null,
          d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedSigner(randomBytes).sign(
            payload,
            invalidPrivateKey as any,
          ),
        ).rejects.toThrow(new JwsInvalid('jwkPrivateKey.crv is missing'));
      });

      it('should throw error for private key with empty crv', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );
        const invalidPrivateKey = {
          kty: 'EC',
          crv: '',
          d: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
          y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
        };

        await expect(
          new FlattenedSigner(randomBytes).sign(
            payload,
            invalidPrivateKey as any,
          ),
        ).rejects.toThrow(new JwsInvalid('jwkPrivateKey.crv is missing'));
      });
    });
  });

  describe('header validation', () => {
    it('should throw error when protectedHeader is called twice', () => {
      expect(() =>
        new FlattenedSigner(randomBytes)
          .protectedHeader({ alg: 'ES256' })
          .protectedHeader({ alg: 'ES256' }),
      ).toThrow(new JwsInvalid('protectedHeader can only be called once'));
    });

    it('should throw error when unprotectedHeader is called twice', () => {
      const header = { kid: 'test' };

      expect(() =>
        new FlattenedSigner(randomBytes)
          .unprotectedHeader(header)
          .unprotectedHeader(header),
      ).toThrow(new JwsInvalid('unprotectedHeader can only be called once'));
    });

    it('should throw error when protected header is missing', async () => {
      const payload = Uint8Array.from(new TextEncoder().encode('Test payload'));

      // Generate P-256 key pair for this test
      const signatureCurve = createSignatureCurve('P-256', randomBytes);
      const rawPrivateKey = signatureCurve.randomPrivateKey();
      const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

      // Try to sign without setting protected header
      await expect(
        new FlattenedSigner(randomBytes).sign(payload, privateKey),
      ).rejects.toThrow(new JwsInvalid('Failed to sign payload'));
    });
  });
});
