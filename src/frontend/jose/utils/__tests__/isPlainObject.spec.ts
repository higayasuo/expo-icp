import { describe, it, expect } from 'vitest';
import { isObjectLike, isPlainObject } from '../isPlainObject';

describe('Plain Object type checks', () => {
  describe('isObjectLike', () => {
    it('should return true for plain objects', () => {
      expect(isObjectLike({})).toBe(true);
      expect(isObjectLike({ key: 'value' })).toBe(true);
      expect(isObjectLike(Object.create(null))).toBe(true);
      expect(isObjectLike(Object.create(Object.prototype))).toBe(true);
    });

    it('should return false for non-object values', () => {
      expect(isObjectLike(null)).toBe(false);
      expect(isObjectLike(undefined)).toBe(false);
      expect(isObjectLike(42)).toBe(false);
      expect(isObjectLike('string')).toBe(false);
      expect(isObjectLike(true)).toBe(false);
    });

    it('should return false for Symbols', () => {
      expect(isObjectLike(Symbol())).toBe(false);
    });

    it('should return false for arrays', () => {
      expect(isObjectLike([])).toBe(false);
      expect(isObjectLike([1, 2, 3])).toBe(false);
    });

    it('should return false for built-in objects', () => {
      expect(isObjectLike(new Date())).toBe(false);
      expect(isObjectLike(new RegExp(''))).toBe(false);
      expect(isObjectLike(new Map())).toBe(false);
      expect(isObjectLike(new Set())).toBe(false);
    });

    it('should return false for functions', () => {
      expect(isObjectLike(() => {})).toBe(false);
      expect(isObjectLike(function () {})).toBe(false);
      expect(isObjectLike(class {})).toBe(false);
      expect(isObjectLike(new Function())).toBe(false);
    });
  });

  describe('isPlainObject', () => {
    it('should return true for plain objects', () => {
      expect(isPlainObject({})).toBe(true);
      expect(isPlainObject({ key: 'value' })).toBe(true);
      expect(isPlainObject(Object.create(null))).toBe(true);
    });

    it('should return false for non-object values', () => {
      expect(isPlainObject(null)).toBe(false);
      expect(isPlainObject(undefined)).toBe(false);
      expect(isPlainObject(42)).toBe(false);
      expect(isPlainObject('string')).toBe(false);
      expect(isPlainObject(true)).toBe(false);
      expect(isPlainObject(Symbol())).toBe(false);
    });

    it('should return false for arrays', () => {
      expect(isPlainObject([])).toBe(false);
      expect(isPlainObject([1, 2, 3])).toBe(false);
    });

    it('should return false for built-in objects', () => {
      expect(isPlainObject(new Date())).toBe(false);
      expect(isPlainObject(new RegExp(''))).toBe(false);
      expect(isPlainObject(new Map())).toBe(false);
      expect(isPlainObject(new Set())).toBe(false);
    });

    it('should work with type assertions', () => {
      interface TestInterface {
        key: string;
      }

      const value: unknown = { key: 'value' };
      if (isPlainObject<TestInterface>(value)) {
        expect(value.key).toBe('value');
      }
    });
  });
});
