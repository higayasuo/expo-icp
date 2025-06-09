import { describe, it, expect } from 'vitest';
import { hasNoDuplicateKeys } from '../hasNoDuplicateKeys';

describe('hasNoDuplicateKeys', () => {
  it('should return true for empty input', () => {
    expect(hasNoDuplicateKeys()).toBe(true);
  });

  it('should return true for single object', () => {
    expect(hasNoDuplicateKeys({ a: 1 })).toBe(true);
  });

  it('should return true for multiple objects with unique keys', () => {
    expect(hasNoDuplicateKeys({ a: 1 }, { b: 2 }, { c: 3 })).toBe(true);
  });

  it('should return false when duplicate keys exist', () => {
    expect(hasNoDuplicateKeys({ a: 1 }, { a: 2 })).toBe(false);
  });

  it('should handle undefined inputs', () => {
    expect(hasNoDuplicateKeys(undefined, { a: 1 })).toBe(true);
    expect(hasNoDuplicateKeys({ a: 1 }, undefined, { b: 2 })).toBe(true);
  });

  it('should handle empty objects', () => {
    expect(hasNoDuplicateKeys({}, { a: 1 })).toBe(true);
    expect(hasNoDuplicateKeys({ a: 1 }, {})).toBe(true);
  });

  it('should handle multiple duplicate keys', () => {
    expect(hasNoDuplicateKeys({ a: 1, b: 2 }, { a: 3, c: 4 })).toBe(false);
  });
});
