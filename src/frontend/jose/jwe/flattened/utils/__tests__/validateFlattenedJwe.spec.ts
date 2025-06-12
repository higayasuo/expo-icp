import { describe, it, expect } from 'vitest';
import { validateFlattenedJwe } from '../validateFlattenedJwe';
import { JweInvalid } from '@/jose/errors/errors';
import { encodeBase64Url } from 'u8a-utils';
import { FlattenedJwe } from '../../../types';

describe('validateFlattenedJwe', () => {
  it('should validate a valid Flattened JWE', () => {
    const jwe: FlattenedJwe = {
      protected: encodeBase64Url(
        new TextEncoder().encode(
          JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
        ),
      ),
      iv: encodeBase64Url(new Uint8Array(12)),
      ciphertext: encodeBase64Url(new Uint8Array(32)),
      tag: encodeBase64Url(new Uint8Array(16)),
    };

    const result = validateFlattenedJwe(jwe);

    expect(result.iv).toEqual(new Uint8Array(12));
    expect(result.ciphertext).toEqual(new Uint8Array(32));
    expect(result.tag).toEqual(new Uint8Array(16));
    expect(result.encryptedKey).toBeUndefined();
    expect(result.aad).toBeUndefined();
    expect(result.joseHeader).toEqual({ alg: 'ECDH-ES', enc: 'A256GCM' });
    expect(result.parsedProtected).toEqual({ alg: 'ECDH-ES', enc: 'A256GCM' });
  });

  it('should validate a Flattened JWE with all optional fields', () => {
    const jwe: FlattenedJwe = {
      protected: encodeBase64Url(
        new TextEncoder().encode(
          JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
        ),
      ),
      header: { kid: 'test-key' },
      unprotected: { cty: 'text/plain' },
      iv: encodeBase64Url(new Uint8Array(12)),
      ciphertext: encodeBase64Url(new Uint8Array(32)),
      tag: encodeBase64Url(new Uint8Array(16)),
      encrypted_key: encodeBase64Url(new Uint8Array(32)),
      aad: encodeBase64Url(new TextEncoder().encode('test-aad')),
    };

    const result = validateFlattenedJwe(jwe);

    expect(result.iv).toEqual(new Uint8Array(12));
    expect(result.ciphertext).toEqual(new Uint8Array(32));
    expect(result.tag).toEqual(new Uint8Array(16));
    expect(result.encryptedKey).toEqual(new Uint8Array(32));
    expect(result.aad).toEqual(
      Uint8Array.from(new TextEncoder().encode('test-aad')),
    );
    expect(result.joseHeader).toEqual({
      alg: 'ECDH-ES',
      enc: 'A256GCM',
      kid: 'test-key',
      cty: 'text/plain',
    });
    expect(result.parsedProtected).toEqual({ alg: 'ECDH-ES', enc: 'A256GCM' });
  });

  it('should throw JweInvalid for non-object input', () => {
    expect(() =>
      validateFlattenedJwe('invalid' as unknown as FlattenedJwe),
    ).toThrow(JweInvalid);
  });

  describe('required fields', () => {
    it('should throw JweInvalid when protected is missing', () => {
      const jwe = {
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when iv is missing', () => {
      const jwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when ciphertext is missing', () => {
      const jwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        tag: encodeBase64Url(new Uint8Array(16)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when tag is missing', () => {
      const jwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });
  });

  describe('invalid base64url', () => {
    it('should throw JweInvalid when protected is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: 'invalid-base64url',
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when iv is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: 'invalid-base64url',
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when ciphertext is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: 'invalid-base64url',
        tag: encodeBase64Url(new Uint8Array(16)),
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when tag is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: 'invalid-base64url',
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when encrypted_key is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
        encrypted_key: 'invalid-base64url',
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });

    it('should throw JweInvalid when aad is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
        aad: 'invalid-base64url',
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
    });
  });

  it('should throw JweInvalid for invalid header', () => {
    const jwe = {
      protected: encodeBase64Url(
        new TextEncoder().encode(
          JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
        ),
      ),
      header: 'invalid',
      iv: encodeBase64Url(new Uint8Array(12)),
      ciphertext: encodeBase64Url(new Uint8Array(32)),
      tag: encodeBase64Url(new Uint8Array(16)),
    } as unknown as FlattenedJwe;

    expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
  });

  it('should throw JweInvalid for invalid unprotected header', () => {
    const jwe = {
      protected: encodeBase64Url(
        new TextEncoder().encode(
          JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
        ),
      ),
      unprotected: 'invalid',
      iv: encodeBase64Url(new Uint8Array(12)),
      ciphertext: encodeBase64Url(new Uint8Array(32)),
      tag: encodeBase64Url(new Uint8Array(16)),
    } as unknown as FlattenedJwe;

    expect(() => validateFlattenedJwe(jwe)).toThrow(JweInvalid);
  });
});
