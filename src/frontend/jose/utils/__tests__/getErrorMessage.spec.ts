import { describe, it, expect } from 'vitest';
import { getErrorMessage } from '../getErrorMessage';

describe('getErrorMessage', () => {
  describe('Error instances', () => {
    it('should extract message from standard Error', () => {
      const error = new Error('This is a test error');
      expect(getErrorMessage(error)).toBe('This is a test error');
    });

    it('should extract message from Error with empty message', () => {
      const error = new Error('');
      expect(getErrorMessage(error)).toBe('');
    });

    it('should extract message from custom Error subclass', () => {
      class CustomError extends Error {
        constructor(message: string) {
          super(message);
          this.name = 'CustomError';
        }
      }

      const error = new CustomError('Custom error message');
      expect(getErrorMessage(error)).toBe('Custom error message');
    });

    it('should extract message from TypeError', () => {
      const error = new TypeError('Type error occurred');
      expect(getErrorMessage(error)).toBe('Type error occurred');
    });

    it('should extract message from ReferenceError', () => {
      const error = new ReferenceError('Reference error occurred');
      expect(getErrorMessage(error)).toBe('Reference error occurred');
    });

    it('should extract message from RangeError', () => {
      const error = new RangeError('Range error occurred');
      expect(getErrorMessage(error)).toBe('Range error occurred');
    });

    it('should extract message from SyntaxError', () => {
      const error = new SyntaxError('Syntax error occurred');
      expect(getErrorMessage(error)).toBe('Syntax error occurred');
    });
  });

  describe('Non-Error objects', () => {
    it('should convert string to string', () => {
      const error = 'Simple string error';
      expect(getErrorMessage(error)).toBe('Simple string error');
    });

    it('should convert empty string to string', () => {
      const error = '';
      expect(getErrorMessage(error)).toBe('');
    });

    it('should convert number to string', () => {
      const error = 42;
      expect(getErrorMessage(error)).toBe('42');
    });

    it('should convert zero to string', () => {
      const error = 0;
      expect(getErrorMessage(error)).toBe('0');
    });

    it('should convert negative number to string', () => {
      const error = -123;
      expect(getErrorMessage(error)).toBe('-123');
    });

    it('should convert boolean true to string', () => {
      const error = true;
      expect(getErrorMessage(error)).toBe('true');
    });

    it('should convert boolean false to string', () => {
      const error = false;
      expect(getErrorMessage(error)).toBe('false');
    });

    it('should convert null to string', () => {
      const error = null;
      expect(getErrorMessage(error)).toBe('null');
    });

    it('should convert undefined to string', () => {
      const error = undefined;
      expect(getErrorMessage(error)).toBe('undefined');
    });

    it('should convert object to string', () => {
      const error = { key: 'value', number: 42 };
      expect(getErrorMessage(error)).toBe('[object Object]');
    });

    it('should convert array to string', () => {
      const error = [1, 2, 3, 'test'];
      expect(getErrorMessage(error)).toBe('1,2,3,test');
    });

    it('should convert empty object to string', () => {
      const error = {};
      expect(getErrorMessage(error)).toBe('[object Object]');
    });

    it('should convert empty array to string', () => {
      const error: unknown[] = [];
      expect(getErrorMessage(error)).toBe('');
    });

    it('should convert function to string', () => {
      const error = () => 'test';
      expect(getErrorMessage(error)).toContain('() =>');
    });

    it('should convert symbol to string', () => {
      const error = Symbol('test');
      expect(getErrorMessage(error)).toBe('Symbol(test)');
    });

    it('should convert BigInt to string', () => {
      const error = BigInt(123);
      expect(getErrorMessage(error)).toBe('123');
    });

    it('should convert Date to string', () => {
      const error = new Date('2023-01-01T00:00:00.000Z');
      expect(getErrorMessage(error)).toMatch(
        /^[A-Z][a-z]{2} [A-Z][a-z]{2} \d{2} \d{4} \d{2}:\d{2}:\d{2} GMT/,
      );
    });
  });

  describe('Edge cases', () => {
    it('should handle object with toString method', () => {
      const error = {
        toString: () => 'Custom toString message',
      };
      expect(getErrorMessage(error)).toBe('Custom toString message');
    });

    it('should handle object with custom toString that throws', () => {
      const error = {
        toString: () => {
          throw new Error('toString error');
        },
      };
      expect(() => getErrorMessage(error)).toThrow('toString error');
    });

    it('should handle object with message property that is not an Error', () => {
      const error = {
        message: 'This is not an Error instance',
      };
      expect(getErrorMessage(error)).toBe('[object Object]');
    });

    it('should handle object with name property that is not an Error', () => {
      const error = {
        name: 'CustomName',
        message: 'Custom message',
      };
      expect(getErrorMessage(error)).toBe('[object Object]');
    });

    it('should handle circular reference object', () => {
      const error: any = {};
      error.self = error;

      // This should not throw and should return a string representation
      const result = getErrorMessage(error);
      expect(typeof result).toBe('string');
      expect(result).toBe('[object Object]');
    });

    it('should handle very large number', () => {
      const error = Number.MAX_SAFE_INTEGER;
      expect(getErrorMessage(error)).toBe('9007199254740991');
    });

    it('should handle very small number', () => {
      const error = Number.MIN_SAFE_INTEGER;
      expect(getErrorMessage(error)).toBe('-9007199254740991');
    });

    it('should handle Infinity', () => {
      const error = Infinity;
      expect(getErrorMessage(error)).toBe('Infinity');
    });

    it('should handle negative Infinity', () => {
      const error = -Infinity;
      expect(getErrorMessage(error)).toBe('-Infinity');
    });

    it('should handle NaN', () => {
      const error = NaN;
      expect(getErrorMessage(error)).toBe('NaN');
    });
  });
});
