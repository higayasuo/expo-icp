import { describe, expect, it } from 'vitest';
import { CompactEncryption } from '../CompactEncryption';
import { FlattenedEncryption } from '../../flattened/FlattenedEncryption';
import { FlattenedDecryption } from '../../flattened/FlattenedDecryption';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createNistCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const curve = createNistCurve('P-256', getRandomBytes);
const aes = new WebAesCipher(getRandomBytes);

describe('CompactEncryption', () => {
  describe('encrypt', () => {
    it('should be decryptable by FlattenedDecryption', async () => {
      const compactEncryption = new CompactEncryption({ curve, aes });
      const decryption = new FlattenedDecryption({ curve, aes });
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.utils.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);

      const compactJwe = await compactEncryption
        .protectedHeader({ alg: 'ECDH-ES', enc: 'A256GCM' })
        .encrypt(plaintext, rawPublicKey);

      const [protectedHeader, encryptedKey, iv, ciphertext, tag] =
        compactJwe.split('.');
      const flattenedJwe = {
        protected: protectedHeader,
        encrypted_key: encryptedKey,
        iv,
        ciphertext,
        tag,
      };

      const result = await decryption.decrypt(flattenedJwe, rawPrivateKey);
      expect(new TextDecoder().decode(result.plaintext)).toBe('Hello, World!');
    });
  });
});
