import { describe, it, expect } from 'vitest';
import { buildKdfOtherInfo } from '../buildKdfOtherInfo';

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

    // Verify algorithm part
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );

    // Verify apu part
    expect(result.slice(11, 18)).toEqual(new Uint8Array([0, 0, 0, 3, 1, 2, 3]));

    // Verify apv part
    expect(result.slice(18, 25)).toEqual(new Uint8Array([0, 0, 0, 3, 4, 5, 6]));

    // Verify keyBitLength part
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

    // Verify algorithm part
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );

    // Verify apu part (empty)
    expect(result.slice(11, 15)).toEqual(new Uint8Array([0, 0, 0, 0]));

    // Verify apv part (empty)
    expect(result.slice(15, 19)).toEqual(new Uint8Array([0, 0, 0, 0]));

    // Verify keyBitLength part
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

    // Verify algorithm part
    expect(result.slice(0, 11)).toEqual(
      new Uint8Array([0, 0, 0, 7, 65, 50, 53, 54, 71, 67, 77]),
    );

    // Verify apu part
    expect(result.slice(11, 16)).toEqual(new Uint8Array([0, 0, 0, 1, 1]));

    // Verify apv part
    expect(result.slice(16, 21)).toEqual(new Uint8Array([0, 0, 0, 1, 2]));

    // Verify keyBitLength part
    expect(result.slice(21, 25)).toEqual(new Uint8Array([0, 0, 0, 128]));
  });
});
