import { describe, expect, it } from 'vitest';
import { CompactEncryption } from '../CompactEncryption';
import { FlattenedDecryption } from '../../flattened/FlattenedDecryption';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createEcdhCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const aes = new WebAesCipher(getRandomBytes);
const curve = createEcdhCurve('P-256', getRandomBytes);

describe('CompactEncryption', () => {
  describe('encrypt', () => {
    it('should be decryptable by FlattenedDecryption', async () => {
      const compactEncryption = new CompactEncryption(aes);
      const decryption = new FlattenedDecryption(aes);
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

      const compactJwe = await compactEncryption
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, jwkPublicKey);

      const [protectedHeader, encryptedKey, iv, ciphertext, tag] =
        compactJwe.split('.');
      const flattenedJwe = {
        protected: protectedHeader,
        encrypted_key: encryptedKey,
        iv,
        ciphertext,
        tag,
      };

      const result = await decryption.decrypt(flattenedJwe, jwkPrivateKey);
      expect(new TextDecoder().decode(result.plaintext)).toBe('Hello, World!');
    });
  });
});
