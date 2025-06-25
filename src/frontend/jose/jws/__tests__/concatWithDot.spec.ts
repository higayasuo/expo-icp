import { describe, expect, it } from 'vitest';
import {
  compareUint8Arrays,
  concatUint8Arrays,
  encodeBase64Url,
} from 'u8a-utils';

describe('concatWithDot', () => {
  it('should produce the same result as string concatenation with dot', () => {
    const header = new Uint8Array([1, 2, 3]);
    const payload = new Uint8Array([4, 5, 6]);
    const encoder = new TextEncoder();

    const headerB64U = encodeBase64Url(header);
    const payloadB64U = encodeBase64Url(payload);
    const result1 = Uint8Array.from(
      encoder.encode(headerB64U + '.' + payloadB64U),
    );

    const result2 = concatUint8Arrays(
      encoder.encode(headerB64U),
      encoder.encode('.'),
      encoder.encode(payloadB64U),
    );

    expect(result1).toEqual(result2);
  });
});
