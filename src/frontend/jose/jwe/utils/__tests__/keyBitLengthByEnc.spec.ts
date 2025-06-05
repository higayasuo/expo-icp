import { describe, it, expect } from 'vitest';
import { keyBitLengthByEnc } from '../keyBitLengthByEnc';

describe('keyBitLengthByEnc', () => {
  it('should return correct key bit length for GCM algorithms', () => {
    expect(keyBitLengthByEnc('A128GCM')).toBe(128);
    expect(keyBitLengthByEnc('A192GCM')).toBe(192);
    expect(keyBitLengthByEnc('A256GCM')).toBe(256);
  });

  it('should return correct key bit length for CBC-HS algorithms', () => {
    expect(keyBitLengthByEnc('A128CBC-HS256')).toBe(256);
    expect(keyBitLengthByEnc('A192CBC-HS384')).toBe(384);
    expect(keyBitLengthByEnc('A256CBC-HS512')).toBe(512);
  });

  it('should throw an error for unsupported algorithms', () => {
    expect(() => keyBitLengthByEnc('UNKNOWN')).toThrow(
      'Unsupported JWE Encryption Algorithm: UNKNOWN',
    );
    expect(() => keyBitLengthByEnc('')).toThrow(
      'Unsupported JWE Encryption Algorithm: ',
    );
  });
});
