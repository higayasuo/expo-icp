import { describe, it, expect } from 'vitest';
import * as jose from 'jose';

describe('JWE Flattened', () => {
  it('should encrypt and decrypt with ECDH-ES and A256GCM', async () => {
    // Generate key pair
    const { privateKey, publicKey } = await jose.generateKeyPair('ECDH-ES');

    // Create plaintext
    const plaintext = Uint8Array.from(
      new TextEncoder().encode('Hello, World!'),
    );

    // Encrypt
    const jwe = await new jose.FlattenedEncrypt(plaintext)
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(publicKey);

    // Decrypt
    const decrypted = await jose.flattenedDecrypt(jwe, privateKey);

    // Verify
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello, World!');
  });

  it('should encrypt and decrypt with apu/apv parameters', async () => {
    // Generate key pair
    const { privateKey, publicKey } = await jose.generateKeyPair('ECDH-ES');

    // Create plaintext
    const plaintext = Uint8Array.from(
      new TextEncoder().encode('Hello, World!'),
    );

    // Create apu/apv
    const apu = Uint8Array.from(new TextEncoder().encode('Alice'));
    const apv = Uint8Array.from(new TextEncoder().encode('Bob'));

    // Encrypt
    const jwe = await new jose.FlattenedEncrypt(plaintext)
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .setKeyManagementParameters({ apu, apv })
      .encrypt(publicKey);

    // Decrypt
    const decrypted = await jose.flattenedDecrypt(jwe, privateKey);

    // Verify
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello, World!');
  });
});
