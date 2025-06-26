import { describe, it, expect } from 'vitest';
import { cekBitLengthByEnc } from '../cekBitLengthByEnc';

describe('keyBitLengthByEnc', () => {
  it('should return correct key bit length for GCM algorithms', () => {
    expect(cekBitLengthByEnc('A128GCM')).toBe(128);
    expect(cekBitLengthByEnc('A192GCM')).toBe(192);
    expect(cekBitLengthByEnc('A256GCM')).toBe(256);
  });

  it('should return correct key bit length for CBC-HS algorithms', () => {
    expect(cekBitLengthByEnc('A128CBC-HS256')).toBe(256);
    expect(cekBitLengthByEnc('A192CBC-HS384')).toBe(384);
    expect(cekBitLengthByEnc('A256CBC-HS512')).toBe(512);
  });

  it('should throw an error for unsupported algorithms', () => {
    expect(() => cekBitLengthByEnc('UNKNOWN')).toThrow(
      'Unsupported JWE Encryption Algorithm: UNKNOWN',
    );
    expect(() => cekBitLengthByEnc('')).toThrow(
      'Unsupported JWE Encryption Algorithm: ',
    );
  });
});
