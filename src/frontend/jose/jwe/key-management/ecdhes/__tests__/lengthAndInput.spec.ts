import { describe, it, expect } from 'vitest';
import { lengthAndInput } from '../lengthAndInput';

/**
 * Tests for lengthAndInput utility
 */
describe('lengthAndInput', () => {
  it('should prepend 4-byte big-endian length to an empty array', () => {
    const input = new Uint8Array([]);
    const result = lengthAndInput(input);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 0]));
  });

  it('should prepend 4-byte big-endian length to a short array', () => {
    const input = new Uint8Array([1, 2, 3]);
    const result = lengthAndInput(input);
    expect(result).toEqual(new Uint8Array([0, 0, 0, 3, 1, 2, 3]));
  });

  it('should prepend 4-byte big-endian length to a longer array', () => {
    const input = new Uint8Array(
      Array.from({ length: 300 }, (_, i) => i % 256),
    );
    const result = lengthAndInput(input);
    expect(result.slice(0, 4)).toEqual(new Uint8Array([0, 0, 1, 44])); // 300 = 0x012C
    expect(result.slice(4)).toEqual(input);
  });

  it('should handle large input size (1MB)', () => {
    const input = new Uint8Array(1024 * 1024); // 1MB
    const result = lengthAndInput(input);
    expect(result.slice(0, 4)).toEqual(new Uint8Array([0, 16, 0, 0])); // 1MB = 0x100000
    expect(result.length).toBe(input.length + 4);
    expect(result.slice(4)).toEqual(input);
  });

  it('should throw RangeError for input larger than 2^32 - 1', () => {
    const input = new Uint8Array(0x100000000);
    expect(() => lengthAndInput(input)).toThrow(RangeError);
    expect(() => lengthAndInput(input)).toThrow('Input too large');
  });

  it('should preserve input data integrity', () => {
    const testCases = [
      new Uint8Array([0, 1, 2, 3, 4, 5]),
      new Uint8Array([255, 254, 253, 252]),
      new Uint8Array(Array.from({ length: 1000 }, (_, i) => i % 256)),
    ];

    testCases.forEach((input) => {
      const result = lengthAndInput(input);
      expect(result.slice(4)).toEqual(input);
    });
  });

  it('should correctly encode length in big-endian format', () => {
    const testCases = [
      { length: 0, expected: [0, 0, 0, 0] },
      { length: 1, expected: [0, 0, 0, 1] },
      { length: 255, expected: [0, 0, 0, 255] },
      { length: 256, expected: [0, 0, 1, 0] },
      { length: 65535, expected: [0, 0, 255, 255] },
      { length: 65536, expected: [0, 1, 0, 0] },
      { length: 16777215, expected: [0, 255, 255, 255] },
      { length: 16777216, expected: [1, 0, 0, 0] },
    ];

    testCases.forEach(({ length, expected }) => {
      const input = new Uint8Array(length);
      const result = lengthAndInput(input);
      expect(result.slice(0, 4)).toEqual(new Uint8Array(expected));
    });
  });
});
