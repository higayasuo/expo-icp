import { describe, it, expect } from 'vitest';
import { areDisjoint } from '../areDisjoint';

describe('areDisjoint', () => {
  it('should return true for empty input', () => {
    expect(areDisjoint()).toBe(true);
  });

  it('should return true for single object', () => {
    expect(areDisjoint({ a: 1 })).toBe(true);
  });

  it('should return true for multiple objects with unique keys', () => {
    expect(areDisjoint({ a: 1 }, { b: 2 }, { c: 3 })).toBe(true);
  });

  it('should return false when duplicate keys exist', () => {
    expect(areDisjoint({ a: 1 }, { a: 2 })).toBe(false);
  });

  it('should handle undefined inputs', () => {
    expect(areDisjoint(undefined, { a: 1 })).toBe(true);
    expect(areDisjoint({ a: 1 }, undefined, { b: 2 })).toBe(true);
  });

  it('should handle empty objects', () => {
    expect(areDisjoint({}, { a: 1 })).toBe(true);
    expect(areDisjoint({ a: 1 }, {})).toBe(true);
  });

  it('should handle multiple duplicate keys', () => {
    expect(areDisjoint({ a: 1, b: 2 }, { a: 3, c: 4 })).toBe(false);
  });
});
