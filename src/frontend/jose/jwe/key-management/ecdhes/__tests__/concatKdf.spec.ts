import { describe, it, expect } from 'vitest';
import { concatKdf } from '../concatKdf';

const sharedSecret = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
const otherInfo = new Uint8Array([9, 10, 11, 12]);

describe('concatKdf', () => {
  it('should return correct number of bytes for 128 bits', () => {
    const key = concatKdf({ sharedSecret, keyBitLength: 128, otherInfo });
    expect(key.length).toBe(16);
  });

  it('should return correct number of bytes for 192 bits', () => {
    const key = concatKdf({ sharedSecret, keyBitLength: 192, otherInfo });
    expect(key.length).toBe(24);
  });

  it('should return correct number of bytes for 256 bits', () => {
    const key = concatKdf({ sharedSecret, keyBitLength: 256, otherInfo });
    expect(key.length).toBe(32);
  });

  it('should return correct number of bytes for 384 bits', () => {
    const key = concatKdf({ sharedSecret, keyBitLength: 384, otherInfo });
    expect(key.length).toBe(48);
  });

  it('should return correct number of bytes for 512 bits', () => {
    const key = concatKdf({ sharedSecret, keyBitLength: 512, otherInfo });
    expect(key.length).toBe(64);
  });
});
