import { describe, expect, it } from 'vitest';
import { encodeSignTarget } from '../encodeSignTarget';
import { encodeBase64Url } from 'u8a-utils';

describe('encodeSignTarget', () => {
  const testHeader = { alg: 'ES256', typ: 'JWT' };
  const testPayload = new Uint8Array([1, 2, 3, 4, 5]);

  describe('b64: true', () => {
    it('should encode signing target with Base64URL encoded payload', () => {
      const result = encodeSignTarget({
        protectedHeader: testHeader,
        payload: testPayload,
        b64: true,
      });

      // Expected: base64url(header).base64url(payload)
      const expectedHeaderB64U = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify(testHeader)),
      );
      const expectedPayloadB64U = encodeBase64Url(testPayload);
      const expectedSignTarget = new TextEncoder().encode(
        `${expectedHeaderB64U}.${expectedPayloadB64U}`,
      );

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe(expectedPayloadB64U);
    });

    it('should handle empty payload', () => {
      const emptyPayload = new Uint8Array(0);
      const result = encodeSignTarget({
        protectedHeader: testHeader,
        payload: emptyPayload,
        b64: true,
      });

      const expectedHeaderB64U = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify(testHeader)),
      );
      const expectedPayloadB64U = encodeBase64Url(emptyPayload);
      const expectedSignTarget = new TextEncoder().encode(
        `${expectedHeaderB64U}.${expectedPayloadB64U}`,
      );

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe(expectedPayloadB64U);
    });

    it('should handle undefined protected header', () => {
      const result = encodeSignTarget({
        protectedHeader: undefined,
        payload: testPayload,
        b64: true,
      });

      const expectedHeaderB64U = '';
      const expectedPayloadB64U = encodeBase64Url(testPayload);
      const expectedSignTarget = new TextEncoder().encode(
        `${expectedHeaderB64U}.${expectedPayloadB64U}`,
      );

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe(expectedPayloadB64U);
    });
  });

  describe('b64: false', () => {
    it('should encode signing target with binary payload', () => {
      const result = encodeSignTarget({
        protectedHeader: testHeader,
        payload: testPayload,
        b64: false,
      });

      // Expected: base64url(header).payload (binary)
      const expectedHeaderB64U = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify(testHeader)),
      );
      const headerWithDot = new TextEncoder().encode(`${expectedHeaderB64U}.`);
      const expectedSignTarget = new Uint8Array([
        ...headerWithDot,
        ...testPayload,
      ]);

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe('');
    });

    it('should handle empty payload', () => {
      const emptyPayload = new Uint8Array(0);
      const result = encodeSignTarget({
        protectedHeader: testHeader,
        payload: emptyPayload,
        b64: false,
      });

      const expectedHeaderB64U = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify(testHeader)),
      );
      const headerWithDot = new TextEncoder().encode(`${expectedHeaderB64U}.`);
      const expectedSignTarget = new Uint8Array([
        ...headerWithDot,
        ...emptyPayload,
      ]);

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe('');
    });

    it('should handle undefined protected header', () => {
      const result = encodeSignTarget({
        protectedHeader: undefined,
        payload: testPayload,
        b64: false,
      });

      const expectedHeaderB64U = '';
      const headerWithDot = new TextEncoder().encode(`${expectedHeaderB64U}.`);
      const expectedSignTarget = new Uint8Array([
        ...headerWithDot,
        ...testPayload,
      ]);

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe('');
    });
  });

  describe('edge cases', () => {
    it('should handle large payload', () => {
      const largePayload = new Uint8Array(1000).fill(42);
      const result = encodeSignTarget({
        protectedHeader: testHeader,
        payload: largePayload,
        b64: true,
      });

      const expectedHeaderB64U = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify(testHeader)),
      );
      const expectedPayloadB64U = encodeBase64Url(largePayload);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe(expectedPayloadB64U);
      expect(result.signTarget.length).toBeGreaterThan(0);
    });

    it('should handle complex header object', () => {
      const complexHeader = {
        alg: 'ES256',
        typ: 'JWT',
        kid: 'test-key-id',
        x5t: 'test-thumbprint',
        crit: ['exp', 'iat'],
      };

      const result = encodeSignTarget({
        protectedHeader: complexHeader,
        payload: testPayload,
        b64: true,
      });

      const expectedHeaderB64U = encodeBase64Url(
        new TextEncoder().encode(JSON.stringify(complexHeader)),
      );
      const expectedPayloadB64U = encodeBase64Url(testPayload);
      const expectedSignTarget = new TextEncoder().encode(
        `${expectedHeaderB64U}.${expectedPayloadB64U}`,
      );

      expect(result.signTarget).toEqual(expectedSignTarget);
      expect(result.protectedHeaderB64U).toBe(expectedHeaderB64U);
      expect(result.payloadB64U).toBe(expectedPayloadB64U);
    });
  });
});
