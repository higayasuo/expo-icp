import { describe, it, expect } from 'vitest';
import { formatError } from '../formatError';

describe('formatError', () => {
  it('should format Error object with prefix', () => {
    const error = new Error('Test error message');
    const result = formatError('Login', error);
    expect(result).toBe('Internet Identity Login: Test error message');
  });

  it('should format string error with prefix', () => {
    const error = 'String error message';
    const result = formatError('Login', error);
    expect(result).toBe('Internet Identity Login: String error message');
  });

  it('should format number error with prefix', () => {
    const error = 404;
    const result = formatError('Login', error);
    expect(result).toBe('Internet Identity Login: 404');
  });

  it('should format object error with prefix', () => {
    const error = { message: 'Object error message' };
    const result = formatError('Login', error);
    expect(result).toBe('Internet Identity Login: [object Object]');
  });

  it('should handle different prefixes', () => {
    const error = new Error('Test error message');
    const result = formatError('Logout', error);
    expect(result).toBe('Internet Identity Logout: Test error message');
  });
});
