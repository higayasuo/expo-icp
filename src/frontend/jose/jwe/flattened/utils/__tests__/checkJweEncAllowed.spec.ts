import { describe, it, expect, vi } from 'vitest';
import { checkJweEncAllowed } from '../checkJweEncAllowed';
import { JweInvalid } from '@/jose/errors';

describe('checkJweEncAllowed', () => {
  it('should not throw when algorithm is allowed', () => {
    const testCases = [
      { enc: 'A128CBC-HS256', allowed: ['A128CBC-HS256', 'A256CBC-HS512'] },
      { enc: 'A256CBC-HS512', allowed: ['A128CBC-HS256', 'A256CBC-HS512'] },
      { enc: 'A128GCM', allowed: ['A128GCM', 'A256GCM'] },
      { enc: 'A256GCM', allowed: ['A128GCM', 'A256GCM'] },
    ];

    testCases.forEach(({ enc, allowed }) => {
      expect(() => checkJweEncAllowed(enc, allowed)).not.toThrow();
    });
  });

  it('should not throw when contentEncryptionAlgorithms is undefined', () => {
    const testCases = ['A128CBC-HS256', 'A256CBC-HS512', 'A128GCM', 'A256GCM'];

    testCases.forEach((enc) => {
      expect(() => checkJweEncAllowed(enc, undefined)).not.toThrow();
    });
  });

  it('should throw JweInvalid when algorithm is not allowed', () => {
    const testCases = [
      { enc: 'A128CBC-HS256', allowed: ['A256CBC-HS512'] },
      { enc: 'A256CBC-HS512', allowed: ['A128CBC-HS256'] },
      { enc: 'A128GCM', allowed: ['A256GCM'] },
      { enc: 'A256GCM', allowed: ['A128GCM'] },
    ];

    testCases.forEach(({ enc, allowed }) => {
      expect(() => checkJweEncAllowed(enc, allowed)).toThrow(JweInvalid);
    });
  });

  it('should log error message when algorithm is not allowed', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error');
    const enc = 'A128CBC-HS256';
    const allowed = ['A256CBC-HS512'];

    expect(() => checkJweEncAllowed(enc, allowed)).toThrow(JweInvalid);
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      '"enc" (Content Encryption Algorithm) is not allowed: %s, allowedAlgorithms: %s',
      enc,
      allowed.join(', '),
    );

    consoleErrorSpy.mockRestore();
  });
});
