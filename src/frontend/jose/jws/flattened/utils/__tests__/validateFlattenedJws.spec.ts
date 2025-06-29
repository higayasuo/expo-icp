import { describe, it, expect } from 'vitest';
import { validateFlattenedJws } from '../validateFlattenedJws';
import { JwsInvalid, JoseInvalid } from '@/jose/errors/errors';
import { encodeBase64Url } from 'u8a-utils';
import { FlattenedJwsInput } from '../../types';

describe('validateFlattenedJws', () => {
  it('should validate a valid Flattened JWS', () => {
    const jws: FlattenedJwsInput = {
      protected: encodeBase64Url(
        new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
      ),
      payload: encodeBase64Url(new TextEncoder().encode('test payload')),
      signature: encodeBase64Url(new Uint8Array(64)),
    };

    const result = validateFlattenedJws(jws);

    expect(result.signature).toEqual(new Uint8Array(64));
    expect(result.joseHeader).toEqual({ alg: 'ES256' });
    expect(result.parsedProtected).toEqual({ alg: 'ES256' });
  });

  it('should validate a Flattened JWS with unprotected header', () => {
    const jws: FlattenedJwsInput = {
      protected: encodeBase64Url(
        new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
      ),
      header: { kid: 'test-key' },
      payload: encodeBase64Url(new TextEncoder().encode('test payload')),
      signature: encodeBase64Url(new Uint8Array(64)),
    };

    const result = validateFlattenedJws(jws);

    expect(result.signature).toEqual(new Uint8Array(64));
    expect(result.joseHeader).toEqual({
      alg: 'ES256',
      kid: 'test-key',
    });
    expect(result.parsedProtected).toEqual({ alg: 'ES256' });
  });

  it('should validate a Flattened JWS with Uint8Array payload', () => {
    const payload = new TextEncoder().encode('test payload');
    const jws: FlattenedJwsInput = {
      protected: encodeBase64Url(
        new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
      ),
      payload,
      signature: encodeBase64Url(new Uint8Array(64)),
    };

    const result = validateFlattenedJws(jws);

    expect(result.signature).toEqual(new Uint8Array(64));
    expect(result.joseHeader).toEqual({ alg: 'ES256' });
    expect(result.parsedProtected).toEqual({ alg: 'ES256' });
  });

  it('should throw JwsInvalid for non-object input', () => {
    expect(() =>
      validateFlattenedJws('invalid' as unknown as FlattenedJwsInput),
    ).toThrow(new JwsInvalid('Flattened JWS must be a plain object'));
  });

  describe('required fields', () => {
    it('should throw JoseInvalid when protected is missing', () => {
      const jws = {
        payload: encodeBase64Url(new TextEncoder().encode('test payload')),
        signature: encodeBase64Url(new Uint8Array(64)),
      } as unknown as FlattenedJwsInput;

      expect(() => validateFlattenedJws(jws)).toThrow(
        new JoseInvalid('"JWS Protected Header" is missing'),
      );
    });

    it('should throw JoseInvalid when signature is missing', () => {
      const jws = {
        protected: encodeBase64Url(
          new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
        ),
        payload: encodeBase64Url(new TextEncoder().encode('test payload')),
      } as unknown as FlattenedJwsInput;

      expect(() => validateFlattenedJws(jws)).toThrow(
        new JoseInvalid('"JWS Signature" is missing'),
      );
    });

    it('should throw JwsInvalid when payload is missing', () => {
      const jws = {
        protected: encodeBase64Url(
          new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
        ),
        signature: encodeBase64Url(new Uint8Array(64)),
      } as unknown as FlattenedJwsInput;

      expect(() => validateFlattenedJws(jws)).toThrow(
        new JwsInvalid('JWS Payload is missing'),
      );
    });
  });

  describe('invalid payload', () => {
    it('should throw JwsInvalid when payload is not string or Uint8Array', () => {
      const jws = {
        protected: encodeBase64Url(
          new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
        ),
        payload: 123,
        signature: encodeBase64Url(new Uint8Array(64)),
      } as unknown as FlattenedJwsInput;

      expect(() => validateFlattenedJws(jws)).toThrow(
        new JwsInvalid('JWS Payload must be a string or Uint8Array'),
      );
    });
  });

  describe('invalid base64url', () => {
    it('should throw JoseInvalid when protected is invalid base64url', () => {
      const jws: FlattenedJwsInput = {
        protected: 'invalid-base64url',
        payload: encodeBase64Url(new TextEncoder().encode('test payload')),
        signature: encodeBase64Url(new Uint8Array(64)),
      };

      expect(() => validateFlattenedJws(jws)).toThrow(
        new JoseInvalid('Failed to base64url decode "JWS Protected Header"'),
      );
    });

    it('should throw JoseInvalid when signature is invalid base64url', () => {
      const jws: FlattenedJwsInput = {
        protected: encodeBase64Url(
          new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
        ),
        payload: encodeBase64Url(new TextEncoder().encode('test payload')),
        signature: 'invalid-base64url',
      };

      expect(() => validateFlattenedJws(jws)).toThrow(
        new JoseInvalid('Failed to base64url decode "JWS Signature"'),
      );
    });
  });

  it('should throw JwsInvalid for invalid header', () => {
    const jws = {
      protected: encodeBase64Url(
        new TextEncoder().encode(JSON.stringify({ alg: 'ES256' })),
      ),
      header: 'invalid',
      payload: encodeBase64Url(new TextEncoder().encode('test payload')),
      signature: encodeBase64Url(new Uint8Array(64)),
    } as unknown as FlattenedJwsInput;

    expect(() => validateFlattenedJws(jws)).toThrow(
      new JwsInvalid('JWS Unprotected Header is invalid'),
    );
  });
});
