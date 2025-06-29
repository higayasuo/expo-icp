import { describe, expect, it } from 'vitest';
import { CompactEncrypter } from '../CompactEncrypter';
import { FlattenedDecrypter } from '../../flattened/FlattenedDecrypter';
import { webCryptoModule } from 'expo-crypto-universal-web';
import { WebAesCipher } from 'aes-universal-web';
import { createEcdhCurve } from 'noble-curves-extended';

const { getRandomBytes } = webCryptoModule;
const aes = new WebAesCipher(getRandomBytes);
const curve = createEcdhCurve('P-256', getRandomBytes);

describe('CompactEncrypter', () => {
  describe('encrypt', () => {
    it('should be decryptable by FlattenedDecrypter', async () => {
      const plaintext = new TextEncoder().encode('Hello, World!');
      const rawPrivateKey = curve.randomPrivateKey();
      const rawPublicKey = curve.getPublicKey(rawPrivateKey, false);
      const jwkPrivateKey = curve.toJwkPrivateKey(rawPrivateKey);
      const jwkPublicKey = curve.toJwkPublicKey(rawPublicKey);

      const compactJwe = await new CompactEncrypter(aes)
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

      const result = await new FlattenedDecrypter(aes).decrypt(
        flattenedJwe,
        jwkPrivateKey,
      );
      expect(new TextDecoder().decode(result.plaintext)).toBe('Hello, World!');
    });
  });
});
