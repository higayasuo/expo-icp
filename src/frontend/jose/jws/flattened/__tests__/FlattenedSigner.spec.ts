import { describe, expect, it, beforeEach } from 'vitest';
import { FlattenedSigner } from '../FlattenedSigner';
import { flattenedVerify } from 'jose';
import { JwsInvalid } from '@/jose/errors';
import { JwkPrivateKey, createSignatureCurve } from 'noble-curves-extended';
import { randomBytes } from '@noble/hashes/utils';
import { encodeBase64Url } from 'u8a-utils';

describe('FlattenedSigner', () => {
  let signer: FlattenedSigner;

  beforeEach(() => {
    // Use real random bytes from @noble/hashes
    signer = new FlattenedSigner(randomBytes);
  });

  describe('signing and verification', () => {
    const curves = [
      { name: 'P-256', alg: 'ES256' },
      { name: 'P-384', alg: 'ES384' },
      { name: 'P-521', alg: 'ES512' },
      { name: 'Ed25519', alg: 'EdDSA' },
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

        const protectedHeader = {
          alg,
          typ: 'JWT',
        };

        const jws = await signer
          .protectedHeader(protectedHeader)
          .sign(payload, privateKey);

        const verified = await flattenedVerify(jws, publicKey);
        expect(verified.payload).toEqual(payload);
        expect(verified.protectedHeader).toEqual(protectedHeader);
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

      const protectedHeader = {
        alg: 'ES256',
        b64: true,
      };

      const jws = await signer
        .protectedHeader(protectedHeader)
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

      const protectedHeader = {
        alg: 'ES256',
        b64: false,
        crit: ['b64'],
      };

      const jws = await signer
        .protectedHeader(protectedHeader)
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

      const protectedHeader = {
        alg: 'ES256',
      };

      const unprotectedHeader = {
        kid: 'test-key-id',
        x5t: 'test-thumbprint',
      };

      const jws = await signer
        .protectedHeader(protectedHeader)
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

        await expect(signer.sign(undefined as any, privateKey)).rejects.toThrow(
          new JwsInvalid('payload is missing'),
        );
      });

      it('should throw error for null payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(signer.sign(null as any, privateKey)).rejects.toThrow(
          new JwsInvalid('payload is missing'),
        );
      });

      it('should throw error for empty payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(signer.sign('' as any, privateKey)).rejects.toThrow(
          new JwsInvalid('payload must be a Uint8Array'),
        );
      });

      it('should throw error for non-Uint8Array payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(
          signer.sign('not a Uint8Array' as any, privateKey),
        ).rejects.toThrow(new JwsInvalid('payload must be a Uint8Array'));
      });

      it('should throw error for array payload', async () => {
        // Generate P-256 key pair for this test
        const signatureCurve = createSignatureCurve('P-256', randomBytes);
        const rawPrivateKey = signatureCurve.randomPrivateKey();
        const privateKey = signatureCurve.toJwkPrivateKey(rawPrivateKey);

        await expect(signer.sign([1, 2, 3] as any, privateKey)).rejects.toThrow(
          new JwsInvalid('payload must be a Uint8Array'),
        );
      });
    });

    describe('jwkPrivateKey validation', () => {
      it('should throw error for missing private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(signer.sign(payload, undefined as any)).rejects.toThrow(
          new JwsInvalid('jwkPrivateKey is missing'),
        );
      });

      it('should throw error for null private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(signer.sign(payload, null as any)).rejects.toThrow(
          new JwsInvalid('jwkPrivateKey is missing'),
        );
      });

      it('should throw error for non-object private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(
          signer.sign(payload, 'not an object' as any),
        ).rejects.toThrow(
          new JwsInvalid('jwkPrivateKey must be a plain object'),
        );
      });

      it('should throw error for array private key', async () => {
        const payload = Uint8Array.from(
          new TextEncoder().encode('Test payload'),
        );

        await expect(signer.sign(payload, [] as any)).rejects.toThrow(
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
          signer.sign(payload, invalidPrivateKey as any),
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
          signer.sign(payload, invalidPrivateKey as any),
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
          signer.sign(payload, invalidPrivateKey as any),
        ).rejects.toThrow(new JwsInvalid('jwkPrivateKey.crv is missing'));
      });
    });
  });

  describe('header validation', () => {
    it('should throw error when protectedHeader is called twice', () => {
      const header = { alg: 'ES256' };
      signer.protectedHeader(header);

      expect(() => signer.protectedHeader(header)).toThrow(
        new JwsInvalid('protectedHeader can only be called once'),
      );
    });

    it('should throw error when unprotectedHeader is called twice', () => {
      const header = { kid: 'test' };
      signer.unprotectedHeader(header);

      expect(() => signer.unprotectedHeader(header)).toThrow(
        new JwsInvalid('unprotectedHeader can only be called once'),
      );
    });
  });
});
