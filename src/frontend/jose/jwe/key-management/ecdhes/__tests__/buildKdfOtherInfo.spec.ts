import { describe, it, expect } from 'vitest';
import { buildKdfOtherInfo } from '../buildKdfOtherInfo';
import { JweInvalid, JweNotSupported } from '@/jose/errors';

describe('buildKdfOtherInfo', () => {
  it('should build correct KDF Other Info structure', () => {
    const params = {
      algorithm: 'A256GCM',
      apu: new Uint8Array([1, 2, 3]),
      apv: new Uint8Array([4, 5, 6]),
      keyBitLength: 256,
    };

    const result = buildKdfOtherInfo(params);

    // Expected structure:
    // algorithm: [0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77] (11 bytes)
    // apu: [0, 0, 0, 3, 1, 2, 3] (7 bytes)
    // apv: [0, 0, 0, 3, 4, 5, 6] (7 bytes)
    // keyBitLength: [0, 0, 1, 0] (4 bytes)
    // Total: 11 + 7 + 7 + 4 = 29 bytes
    expect(result.length).toBe(29);
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );
    expect(result.slice(11, 18)).toEqual(new Uint8Array([0, 0, 0, 3, 1, 2, 3]));
    expect(result.slice(18, 25)).toEqual(new Uint8Array([0, 0, 0, 3, 4, 5, 6]));
    expect(result.slice(25, 29)).toEqual(new Uint8Array([0, 0, 1, 0]));
  });

  it('should handle empty arrays for apu and apv', () => {
    const params = {
      algorithm: 'A256GCM',
      apu: new Uint8Array([]),
      apv: new Uint8Array([]),
      keyBitLength: 256,
    };

    const result = buildKdfOtherInfo(params);

    // Expected structure:
    // algorithm: [0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77] (11 bytes)
    // apu: [0, 0, 0, 0] (4 bytes)
    // apv: [0, 0, 0, 0] (4 bytes)
    // keyBitLength: [0, 0, 1, 0] (4 bytes)
    // Total: 11 + 4 + 4 + 4 = 23 bytes
    expect(result.length).toBe(23);
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );
    expect(result.slice(11, 15)).toEqual(new Uint8Array([0, 0, 0, 0]));
    expect(result.slice(15, 19)).toEqual(new Uint8Array([0, 0, 0, 0]));
    expect(result.slice(19, 23)).toEqual(new Uint8Array([0, 0, 1, 0]));
  });

  it('should handle omitted apu and apv (undefined)', () => {
    const params = {
      algorithm: 'A256GCM',
      keyBitLength: 256,
    };
    // apu and apv are omitted
    const result = buildKdfOtherInfo(params);
    // Should behave as if empty Uint8Array were passed
    expect(result.length).toBe(23);
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );
    expect(result.slice(11, 15)).toEqual(new Uint8Array([0, 0, 0, 0]));
    expect(result.slice(15, 19)).toEqual(new Uint8Array([0, 0, 0, 0]));
    expect(result.slice(19, 23)).toEqual(new Uint8Array([0, 0, 1, 0]));
  });

  it('should handle different key bit lengths', () => {
    const params = {
      algorithm: 'A256GCM',
      apu: new Uint8Array([1]),
      apv: new Uint8Array([2]),
      keyBitLength: 128,
    };

    const result = buildKdfOtherInfo(params);

    // Expected structure:
    // algorithm: [0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77] (11 bytes)
    // apu: [0, 0, 0, 1, 1] (5 bytes)
    // apv: [0, 0, 0, 1, 2] (5 bytes)
    // keyBitLength: [0, 0, 0, 128] (4 bytes)
    // Total: 11 + 5 + 5 + 4 = 25 bytes
    expect(result.length).toBe(25);
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );
    expect(result.slice(11, 16)).toEqual(new Uint8Array([0, 0, 0, 1, 1]));
    expect(result.slice(16, 21)).toEqual(new Uint8Array([0, 0, 0, 1, 2]));
    expect(result.slice(21, 25)).toEqual(new Uint8Array([0, 0, 0, 128]));
  });

  it('should throw JweNotSupported for non-ASCII algorithm names', () => {
    const params = {
      algorithm: 'アルゴリズム', // Japanese for "algorithm"
      keyBitLength: 256,
    };
    expect(() => buildKdfOtherInfo(params)).toThrow(JweNotSupported);
    expect(() => buildKdfOtherInfo(params)).toThrow(
      '"enc" (Content Encryption Algorithm) is not supported',
    );
  });

  it('should throw JweInvalid for APU longer than 32 bytes', () => {
    const params = {
      algorithm: 'A256GCM',
      apu: new Uint8Array(33),
      keyBitLength: 256,
    };
    expect(() => buildKdfOtherInfo(params)).toThrow(JweInvalid);
    expect(() => buildKdfOtherInfo(params)).toThrow(
      'APU/APV must be ≤32 bytes',
    );
  });

  it('should throw JweInvalid for APV longer than 32 bytes', () => {
    const params = {
      algorithm: 'A256GCM',
      apv: new Uint8Array(33),
      keyBitLength: 256,
    };
    expect(() => buildKdfOtherInfo(params)).toThrow(JweInvalid);
    expect(() => buildKdfOtherInfo(params)).toThrow(
      'APU/APV must be ≤32 bytes',
    );
  });

  it('should throw JweNotSupported for unsupported algorithm', () => {
    const params = {
      algorithm: 'UNSUPPORTED',
      keyBitLength: 256,
    };
    expect(() => buildKdfOtherInfo(params)).toThrow(JweNotSupported);
    expect(() => buildKdfOtherInfo(params)).toThrow(
      '"enc" (Content Encryption Algorithm) is not supported',
    );
  });

  it('should handle maximum allowed APU/APV size (32 bytes)', () => {
    const params = {
      algorithm: 'A256GCM',
      apu: new Uint8Array(32),
      apv: new Uint8Array(32),
      keyBitLength: 256,
    };
    const result = buildKdfOtherInfo(params);
    // Expected structure:
    // algorithm: [0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77] (11 bytes)
    // apu: [0, 0, 0, 32, ...] (36 bytes)
    // apv: [0, 0, 0, 32, ...] (36 bytes)
    // keyBitLength: [0, 0, 1, 0] (4 bytes)
    // Total: 11 + 36 + 36 + 4 = 87 bytes
    expect(result.length).toBe(87);
    expect(result.slice(11, 15)).toEqual(new Uint8Array([0, 0, 0, 32]));
    expect(result.slice(47, 51)).toEqual(new Uint8Array([0, 0, 0, 32]));
  });
});
