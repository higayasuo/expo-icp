import { describe, it, expect } from 'vitest';
import { validateFlattenedJwe } from '../validateFlattenedJwe';
import { JweInvalid, JoseInvalid } from '@/jose/errors/errors';
import { encodeBase64Url } from 'u8a-utils';
import { FlattenedJwe } from '@/jose/jwe/flattened/types';

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
    expect(() =>
      validateFlattenedJwe('invalid' as unknown as FlattenedJwe),
    ).toThrow('Flattened JWE must be a plain object');
  });

  describe('required fields', () => {
    it('should throw JoseInvalid when protected is missing', () => {
      const jwe = {
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        '"JWE Protected Header" is missing',
      );
    });

    it('should throw JoseInvalid when iv is missing', () => {
      const jwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        '"JWE Initialization Vector" is missing',
      );
    });

    it('should throw JoseInvalid when ciphertext is missing', () => {
      const jwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        tag: encodeBase64Url(new Uint8Array(16)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        '"JWE Ciphertext" is missing',
      );
    });

    it('should throw JoseInvalid when tag is missing', () => {
      const jwe = {
        protected: encodeBase64Url(
          new TextEncoder().encode(
            JSON.stringify({ alg: 'ECDH-ES', enc: 'A256GCM' }),
          ),
        ),
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
      } as unknown as FlattenedJwe;

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        '"JWE Authentication Tag" is missing',
      );
    });
  });

  describe('invalid base64url', () => {
    it('should throw JoseInvalid when protected is invalid base64url', () => {
      const jwe: FlattenedJwe = {
        protected: 'invalid-base64url',
        iv: encodeBase64Url(new Uint8Array(12)),
        ciphertext: encodeBase64Url(new Uint8Array(32)),
        tag: encodeBase64Url(new Uint8Array(16)),
      };

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        'Failed to base64url decode "JWE Protected Header"',
      );
    });

    it('should throw JoseInvalid when iv is invalid base64url', () => {
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

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        'Failed to base64url decode "JWE Initialization Vector"',
      );
    });

    it('should throw JoseInvalid when ciphertext is invalid base64url', () => {
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

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        'Failed to base64url decode "JWE Ciphertext"',
      );
    });

    it('should throw JoseInvalid when tag is invalid base64url', () => {
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

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        'Failed to base64url decode "JWE Authentication Tag"',
      );
    });

    it('should throw JoseInvalid when encrypted_key is invalid base64url', () => {
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

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        'Failed to base64url decode "JWE Encrypted Key"',
      );
    });

    it('should throw JoseInvalid when aad is invalid base64url', () => {
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

      expect(() => validateFlattenedJwe(jwe)).toThrow(JoseInvalid);
      expect(() => validateFlattenedJwe(jwe)).toThrow(
        'Failed to base64url decode "JWE Additional Authenticated Data"',
      );
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
    expect(() => validateFlattenedJwe(jwe)).toThrow(
      'JWE Per-Recipient Unprotected Header is invalid',
    );
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
    expect(() => validateFlattenedJwe(jwe)).toThrow(
      'JWE Shared Unprotected Header is invalid',
    );
  });
});
