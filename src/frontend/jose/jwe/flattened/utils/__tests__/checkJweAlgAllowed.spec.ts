import { describe, it, expect, vi } from 'vitest';
import { checkJweAlgAllowed } from '../checkJweAlgAllowed';
import { JweInvalid } from '@/jose/errors';

describe('checkJweAlgAllowed', () => {
  it('should not throw when algorithm is allowed', () => {
    const testCases = [
      { alg: 'ECDH-ES', allowed: ['ECDH-ES', 'RSA-OAEP'] },
      { alg: 'RSA-OAEP', allowed: ['ECDH-ES', 'RSA-OAEP'] },
      { alg: 'A128KW', allowed: ['A128KW', 'A256KW'] },
    ];

    testCases.forEach(({ alg, allowed }) => {
      expect(() => checkJweAlgAllowed(alg, allowed)).not.toThrow();
    });
  });

  it('should not throw for non-PBES2 algorithms when keyManagementAlgorithms is undefined', () => {
    const testCases = ['ECDH-ES', 'RSA-OAEP', 'A128KW', 'A256KW'];

    testCases.forEach((alg) => {
      expect(() => checkJweAlgAllowed(alg, undefined)).not.toThrow();
    });
  });

  it('should throw JweInvalid when algorithm is not allowed', () => {
    const testCases = [
      { alg: 'ECDH-ES', allowed: ['RSA-OAEP'] },
      { alg: 'RSA-OAEP', allowed: ['ECDH-ES'] },
      { alg: 'A128KW', allowed: ['A256KW'] },
    ];

    testCases.forEach(({ alg, allowed }) => {
      expect(() => checkJweAlgAllowed(alg, allowed)).toThrow(JweInvalid);
    });
  });

  it('should throw JweInvalid for PBES2 algorithms when keyManagementAlgorithms is undefined', () => {
    const testCases = [
      'PBES2-HS256+A128KW',
      'PBES2-HS384+A192KW',
      'PBES2-HS512+A256KW',
    ];

    testCases.forEach((alg) => {
      expect(() => checkJweAlgAllowed(alg, undefined)).toThrow(JweInvalid);
    });
  });

  it('should log error message when algorithm is not allowed', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error');
    const alg = 'ECDH-ES';
    const allowed = ['RSA-OAEP'];

    expect(() => checkJweAlgAllowed(alg, allowed)).toThrow(JweInvalid);
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      '"alg" (Key Management Algorithm) is not allowed: %s, allowedAlgorithms: %s',
      alg,
      allowed.join(', '),
    );

    consoleErrorSpy.mockRestore();
  });

  it('should log error message for PBES2 algorithms when keyManagementAlgorithms is undefined', () => {
    const consoleErrorSpy = vi.spyOn(console, 'error');
    const alg = 'PBES2-HS256+A128KW';

    expect(() => checkJweAlgAllowed(alg, undefined)).toThrow(JweInvalid);
    expect(consoleErrorSpy).toHaveBeenCalledWith(
      '"alg" (Key Management Algorithm) is not allowed: %s, allowedAlgorithms: %s',
      alg,
      '',
    );

    consoleErrorSpy.mockRestore();
  });
});
