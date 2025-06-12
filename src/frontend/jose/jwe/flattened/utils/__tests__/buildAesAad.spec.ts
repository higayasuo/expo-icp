import { describe, it, expect } from 'vitest';
import { buildAesAad } from '../buildAesAad';
import { encodeBase64Url } from 'u8a-utils';

const encoder = new TextEncoder();

describe('buildAesAad', () => {
  it('should return encoded protected header when no AAD is provided', () => {
    const protectedHeader = { alg: 'ECDH-ES', enc: 'A256GCM' };
    const protectedHeaderB64U = encodeBase64Url(
      encoder.encode(JSON.stringify(protectedHeader)),
    );

    const result = buildAesAad(protectedHeaderB64U, undefined);
    expect(result).toEqual(encoder.encode(protectedHeaderB64U));
  });

  it('should return encoded concatenated string when AAD is provided', () => {
    const protectedHeader = { alg: 'ECDH-ES', enc: 'A256GCM' };
    const protectedHeaderB64U = encodeBase64Url(
      encoder.encode(JSON.stringify(protectedHeader)),
    );
    const aad = encoder.encode('test-aad');
    const aadB64U = encodeBase64Url(aad);

    const result = buildAesAad(protectedHeaderB64U, aadB64U);
    expect(result).toEqual(encoder.encode(`${protectedHeaderB64U}.${aadB64U}`));
  });

  it('should handle empty protected header', () => {
    const aad = encoder.encode('test-aad');
    const aadB64U = encodeBase64Url(aad);

    const result = buildAesAad('', aadB64U);
    expect(result).toEqual(encoder.encode(`.${aadB64U}`));
  });
});
