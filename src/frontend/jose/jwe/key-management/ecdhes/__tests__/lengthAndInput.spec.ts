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
});
