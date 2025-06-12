import { describe, it, expect } from 'vitest';
import { validateStringArrayAsSet } from '../validateStringArrayAsSet';

describe('validateStringArrayAsSet', () => {
  it('should return a Set of strings when given a valid string array', () => {
    const input = ['a', 'b', 'c'];
    const result = validateStringArrayAsSet(input, 'test');

    expect(result).toBeInstanceOf(Set);
    expect(Array.from(result!)).toEqual(['a', 'b', 'c']);
  });

  it('should return undefined when given undefined', () => {
    const result = validateStringArrayAsSet(undefined, 'test');

    expect(result).toBeUndefined();
  });

  it('should throw TypeError when given a non-array value', () => {
    const testCases = [
      { value: 'string', name: 'string' },
      { value: 123, name: 'number' },
      { value: {}, name: 'object' },
      { value: null, name: 'null' },
      { value: true, name: 'boolean' },
    ];

    testCases.forEach(({ value, name }) => {
      expect(() => validateStringArrayAsSet(value, name)).toThrow(
        new TypeError(`${name} must be an array`),
      );
    });
  });

  it('should throw TypeError when array contains non-string elements', () => {
    const testCases = [
      { value: ['a', 1, 'c'], name: 'mixed array' },
      { value: [true, 'b', 'c'], name: 'boolean in array' },
      { value: ['a', {}, 'c'], name: 'object in array' },
      { value: ['a', null, 'c'], name: 'null in array' },
      { value: ['a', undefined, 'c'], name: 'undefined in array' },
    ];

    testCases.forEach(({ value, name }) => {
      expect(() => validateStringArrayAsSet(value, name)).toThrow(
        new TypeError(`${name} must be an array of strings`),
      );
    });
  });
});
