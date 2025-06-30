import { describe, it, expect } from 'vitest';
import { encodeVerifyTarget } from '../encodeVerifyTarget';
import { encodeSignTarget } from '../encodeSignTarget';
import { randomBytes } from '@noble/hashes/utils';

describe('encodeVerifyTarget', () => {
  describe('b64=false (raw payload)', () => {
    it('should encode verification target with Uint8Array payload', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"
      const b64 = false;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      // Verify target should be: encoder.encode("eyJhbGciOiJFUzI1NiJ9.") + payload
      const expectedHeader = Uint8Array.from(
        new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.'),
      );
      const expectedTarget = new Uint8Array([...expectedHeader, ...payload]);

      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(payload);
    });

    it('should throw error when payload is string with b64=false', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = 'Hello';
      const b64 = false;

      expect(() => {
        encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });
      }).toThrow('Payload must be a Uint8Array when b64=false');
    });

    it('should handle empty Uint8Array payload', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = new Uint8Array([]);
      const b64 = false;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedHeader = Uint8Array.from(
        new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.'),
      );
      expect(result.verifyTarget).toEqual(expectedHeader);
      expect(result.payload).toEqual(new Uint8Array([]));
    });

    it('should handle large Uint8Array payload', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = randomBytes(1024);
      const b64 = false;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedHeader = Uint8Array.from(
        new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.'),
      );
      const expectedTarget = new Uint8Array([...expectedHeader, ...payload]);

      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(payload);
    });
  });

  describe('b64=true (base64url encoded payload)', () => {
    it('should encode verification target with base64url string payload', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = 'SGVsbG8'; // base64url encoded "Hello"
      const b64 = true;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      // Verify target should be: encoder.encode("eyJhbGciOiJFUzI1NiJ9.SGVsbG8")
      const expectedTarget = Uint8Array.from(
        new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.SGVsbG8'),
      );
      const expectedPayload = new Uint8Array([72, 101, 108, 108, 111]); // "Hello"

      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(expectedPayload);
    });

    it('should throw error when payload is Uint8Array with b64=true', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = new Uint8Array([72, 101, 108, 108, 111]);
      const b64 = true;

      expect(() => {
        encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });
      }).toThrow('Payload must be a string when b64=true');
    });

    it('should handle empty base64url string payload', () => {
      const protectedHeaderB64U = 'eyJhbGciOiJFUzI1NiJ9';
      const payload = ''; // empty base64url string
      const b64 = true;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedTarget = Uint8Array.from(
        new TextEncoder().encode('eyJhbGciOiJFUzI1NiJ9.'),
      );
      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(new Uint8Array([]));
    });

    it('should handle complex base64url payload', () => {
      const protectedHeaderB64U =
        'eyJhbGciOiJFUzI1NiIsImJ2IjoiUyIsImN0eSI6IkpXVCJ9';
      const payload =
        'eyJpc3MiOiJqb2UiLCJhdWQiOiJodHRwczovL2p3dC5pbyIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYmYiOjE0NDQ0Nzg0MDAsImV4cCI6MTQ0NDQ4MjAwMCwiaWF0IjoxNDQ0NDc4NDAwfQ';
      const b64 = true;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedTarget = Uint8Array.from(
        new TextEncoder().encode(`${protectedHeaderB64U}.${payload}`),
      );
      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toBeInstanceOf(Uint8Array);
      expect(result.payload.length).toBeGreaterThan(0);
    });
  });

  describe('edge cases', () => {
    it('should handle empty protected header', () => {
      const protectedHeaderB64U = '';
      const payload = new Uint8Array([72, 101, 108, 108, 111]);
      const b64 = false;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedHeader = Uint8Array.from(new TextEncoder().encode('.'));
      const expectedTarget = new Uint8Array([...expectedHeader, ...payload]);

      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(payload);
    });

    it('should handle empty protected header with b64=true', () => {
      const protectedHeaderB64U = '';
      const payload = 'SGVsbG8';
      const b64 = true;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedTarget = Uint8Array.from(
        new TextEncoder().encode(`.${payload}`),
      );
      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(new Uint8Array([72, 101, 108, 108, 111]));
    });

    it('should handle special characters in protected header', () => {
      const protectedHeaderB64U =
        'eyJhbGciOiJFUzI1NiIsImN0eSI6IkpXVCIsImtpZCI6IjEyMzQ1Njc4OTAiLCJ4NXUiOiJodHRwczovL2p3dC5pbyJ9';
      const payload = new Uint8Array([72, 101, 108, 108, 111]);
      const b64 = false;

      const result = encodeVerifyTarget({ protectedHeaderB64U, payload, b64 });

      const expectedHeader = Uint8Array.from(
        new TextEncoder().encode(`${protectedHeaderB64U}.`),
      );
      const expectedTarget = new Uint8Array([...expectedHeader, ...payload]);

      expect(result.verifyTarget).toEqual(expectedTarget);
      expect(result.payload).toEqual(payload);
    });
  });

  describe('consistency with encodeSignTarget', () => {
    describe('b64=false (raw payload)', () => {
      it('should produce consistent targets with encodeSignTarget for b64=false', () => {
        const protectedHeader = { alg: 'ES256' };
        const payload = randomBytes(100);
        const b64 = false;

        // Get sign target
        const signTarget = encodeSignTarget({ protectedHeader, payload, b64 });

        // Get verify target using the same inputs
        const verifyTarget = encodeVerifyTarget({
          protectedHeaderB64U: signTarget.protectedHeaderB64U,
          payload,
          b64,
        });

        // The targets should be identical
        expect(verifyTarget.verifyTarget).toEqual(signTarget.signTarget);
      });

      it('should produce consistent targets with empty payload', () => {
        const protectedHeader = { alg: 'ES256' };
        const payload = new Uint8Array([]);
        const b64 = false;

        // Get sign target
        const signTarget = encodeSignTarget({ protectedHeader, payload, b64 });

        // Get verify target
        const verifyTarget = encodeVerifyTarget({
          protectedHeaderB64U: signTarget.protectedHeaderB64U,
          payload,
          b64,
        });

        // The targets should be identical
        expect(verifyTarget.verifyTarget).toEqual(signTarget.signTarget);
      });

      it('should produce consistent targets with complex header', () => {
        const protectedHeader = {
          alg: 'ES256',
          typ: 'JWT',
          kid: '1234567890',
          x5u: 'https://jwt.io',
        };
        const payload = randomBytes(200);
        const b64 = false;

        // Get sign target
        const signTarget = encodeSignTarget({ protectedHeader, payload, b64 });

        // Get verify target
        const verifyTarget = encodeVerifyTarget({
          protectedHeaderB64U: signTarget.protectedHeaderB64U,
          payload,
          b64,
        });

        // The targets should be identical
        expect(verifyTarget.verifyTarget).toEqual(signTarget.signTarget);
      });
    });

    describe('b64=true (base64url encoded payload)', () => {
      it('should produce consistent targets with encodeSignTarget for b64=true', () => {
        const protectedHeader = { alg: 'ES256' };
        const payload = randomBytes(100);
        const b64 = true;

        // Get sign target
        const signTarget = encodeSignTarget({ protectedHeader, payload, b64 });

        // Get verify target using the base64url encoded payload
        const verifyTarget = encodeVerifyTarget({
          protectedHeaderB64U: signTarget.protectedHeaderB64U,
          payload: signTarget.payloadB64U,
          b64,
        });

        // The targets should be identical
        expect(verifyTarget.verifyTarget).toEqual(signTarget.signTarget);
      });

      it('should produce consistent targets with empty payload', () => {
        const protectedHeader = { alg: 'ES256' };
        const payload = new Uint8Array([]);
        const b64 = true;

        // Get sign target
        const signTarget = encodeSignTarget({ protectedHeader, payload, b64 });

        // Get verify target using the base64url encoded payload
        const verifyTarget = encodeVerifyTarget({
          protectedHeaderB64U: signTarget.protectedHeaderB64U,
          payload: signTarget.payloadB64U,
          b64,
        });

        // The targets should be identical
        expect(verifyTarget.verifyTarget).toEqual(signTarget.signTarget);
      });

      it('should produce consistent targets with complex header', () => {
        const protectedHeader = {
          alg: 'ES256',
          typ: 'JWT',
          kid: '1234567890',
          x5u: 'https://jwt.io',
        };
        const payload = randomBytes(200);
        const b64 = true;

        // Get sign target
        const signTarget = encodeSignTarget({ protectedHeader, payload, b64 });

        // Get verify target using the base64url encoded payload
        const verifyTarget = encodeVerifyTarget({
          protectedHeaderB64U: signTarget.protectedHeaderB64U,
          payload: signTarget.payloadB64U,
          b64,
        });

        // The targets should be identical
        expect(verifyTarget.verifyTarget).toEqual(signTarget.signTarget);
      });
    });
  });
});
