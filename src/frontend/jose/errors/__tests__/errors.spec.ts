import { describe, it, expect } from 'vitest';
import {
  AbstractJoseError,
  JoseGeneric,
  JoseNotSupported,
  JweInvalid,
  JwsInvalid,
} from '../errors';

describe('JOSE Errors', () => {
  describe('JoseGeneric', () => {
    it('should create with correct properties', () => {
      const error = new JoseGeneric('test message');
      expect(error).toBeInstanceOf(AbstractJoseError);
      expect(error.code).toBe('ERR_JOSE_GENERIC');
      expect(error.message).toBe('test message');
      expect(error.name).toBe('JoseGeneric');
    });

    it('should handle error with cause', () => {
      const cause = new Error('original error');
      const error = new JoseGeneric('wrapped error', { cause });
      expect(error.cause).toBe(cause);
    });

    it('should handle error without message', () => {
      const error = new JoseGeneric();
      expect(error.message).toBe('');
    });

    it('should have stack trace', () => {
      const error = new JoseGeneric();
      expect(error.stack).toBeDefined();
    });
  });

  describe('JoseNotSupported', () => {
    it('should create with correct properties', () => {
      const error = new JoseNotSupported('not supported feature');
      expect(error).toBeInstanceOf(AbstractJoseError);
      expect(error.code).toBe('ERR_JOSE_NOT_SUPPORTED');
      expect(error.message).toBe('not supported feature');
      expect(error.name).toBe('JoseNotSupported');
    });

    it('should handle error with cause', () => {
      const cause = new Error('original error');
      const error = new JoseNotSupported('wrapped error', { cause });
      expect(error.cause).toBe(cause);
    });
  });

  describe('JweInvalid', () => {
    it('should create with correct properties', () => {
      const error = new JweInvalid('invalid JWE');
      expect(error).toBeInstanceOf(AbstractJoseError);
      expect(error.code).toBe('ERR_JWE_INVALID');
      expect(error.message).toBe('invalid JWE');
      expect(error.name).toBe('JweInvalid');
    });

    it('should handle error with cause', () => {
      const cause = new Error('original error');
      const error = new JweInvalid('wrapped error', { cause });
      expect(error.cause).toBe(cause);
    });
  });

  describe('JwsInvalid', () => {
    it('should create with correct properties', () => {
      const error = new JwsInvalid('invalid JWS');
      expect(error).toBeInstanceOf(AbstractJoseError);
      expect(error.code).toBe('ERR_JWS_INVALID');
      expect(error.message).toBe('invalid JWS');
      expect(error.name).toBe('JwsInvalid');
    });

    it('should handle error with cause', () => {
      const cause = new Error('original error');
      const error = new JwsInvalid('wrapped error', { cause });
      expect(error.cause).toBe(cause);
    });
  });
});
