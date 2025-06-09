import { describe, it, expect } from 'vitest';
import * as jose from 'jose';
import { FlattenedEncrypt } from '../FlattenedEncrypt';

import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;

const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('JWE Flattened', () => {
  it('should encrypt and decrypt with ECDH-ES and A256GCM', async () => {
    // Generate key pair
    // const { privateKey, publicKey } = await jose.generateKeyPair('ECDH-ES');
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);
    const publicKey = await jose.importJWK(jwkPublicKey, 'ECDH-ES');
    const privateKey = await jose.importJWK(jwkPrivateKey, 'ECDH-ES');

    // Create plaintext
    const plaintext = Uint8Array.from(
      new TextEncoder().encode('Hello, World!'),
    );

    // Encrypt
    const jwe = await new jose.FlattenedEncrypt(plaintext)
      .setProtectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(publicKey);

    const myJwe = await new FlattenedEncrypt({
      curve,
      aes,
      plaintext,
    })
      .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .encrypt(rawPublicKey);

    console.log(myJwe);

    // Decrypt
    const decrypted = await jose.flattenedDecrypt(jwe, privateKey);
    const myDecrypted = await jose.flattenedDecrypt(myJwe, privateKey);

    // Verify
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello, World!');
    expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
      'Hello, World!',
    );
  });

  it('should encrypt and decrypt with apu/apv parameters', async () => {
    // Generate key pair
    const rawPrivateKey = curve.utils.randomPrivateKey();
    const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
    const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
    const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);
    const publicKey = await jose.importJWK(jwkPublicKey, 'ECDH-ES');
    const privateKey = await jose.importJWK(jwkPrivateKey, 'ECDH-ES');

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

    const myJwe = await new FlattenedEncrypt({
      curve,
      aes,
      plaintext,
    })
      .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
      .keyManagementParameters({ apu, apv })
      .encrypt(rawPublicKey);

    console.log(myJwe);

    // Decrypt
    const decrypted = await jose.flattenedDecrypt(jwe, privateKey);
    const myDecrypted = await jose.flattenedDecrypt(myJwe, privateKey);

    // Verify
    expect(new TextDecoder().decode(decrypted.plaintext)).toBe('Hello, World!');
    expect(new TextDecoder().decode(myDecrypted.plaintext)).toBe(
      'Hello, World!',
    );
  });
});
