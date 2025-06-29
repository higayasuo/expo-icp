/**
 * Decrypting JSON Web Encryption (JWE) in Flattened JSON Serialization
 *
 * @module
 */

import { JweInvalid } from '@/jose/errors/errors.js';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { validateCrit } from '@/jose/utils/validateCrit';
import { DecryptOptions } from '@/jose/jwe/types';
import { FlattenedDecryptResult, FlattenedJwe } from './types';
import { validateFlattenedJwe } from './utils/validateFlattenedJwe';
import { validateJweAlg } from '@/jose/jwe/utils/validateJweAlg';
import { validateJweEnc } from '@/jose/jwe/utils/validateJweEnc';
import { checkJweAlgAllowed } from './utils/checkJweAlgAllowed';
import { checkJweEncAllowed } from './utils/checkJweEncAllowed';
import { createEcdhCurve, JwkPrivateKey } from 'noble-curves-extended';
import { AesCipher } from 'aes-universal';
import { deriveDecryptionKeyWithMitigation } from './utils/deriveDecryptionKeyWithMitigation';
import { encodeAesAad } from './utils/encodeAesAad';

/**
 * Class representing the Flattened Decrypter for JSON Web Encryption (JWE).
 */
export class FlattenedDecrypter {
  #aes: AesCipher;

  /**
   * Creates an instance of FlattenedDecrypter.
   *
   * @param {AesCipher} aes - An instance of AesCipher used for decryption operations.
   */
  constructor(aes: AesCipher) {
    this.#aes = aes;
  }

  /**
   * Decrypts a Flattened JWE.
   *
   * @param {FlattenedJwe} jwe - The Flattened JWE object to decrypt.
   * @param {JwkPrivateKey} myJwkPrivateKey - The JWK private key used for decryption.
   * @param {DecryptOptions} [options] - Optional decryption options.
   * @returns {Promise<FlattenedDecryptResult>} A promise that resolves to the decryption result.
   * @throws {JweInvalid} If any required parameter is missing or invalid, or if decryption fails.
   */
  async decrypt(
    jwe: FlattenedJwe,
    myJwkPrivateKey: JwkPrivateKey,
    options?: DecryptOptions,
  ): Promise<FlattenedDecryptResult> {
    if (!jwe) {
      throw new JweInvalid('jwe is missing');
    }

    if (!isPlainObject(jwe)) {
      throw new JweInvalid('Flattened JWE must be a plain object');
    }

    if (!myJwkPrivateKey) {
      throw new JweInvalid('myJwkPrivateKey is missing');
    }

    if (!isPlainObject(myJwkPrivateKey)) {
      throw new JweInvalid('myJwkPrivateKey must be a plain object');
    }

    if (!myJwkPrivateKey.crv) {
      throw new JweInvalid('myJwkPrivateKey.crv is missing');
    }

    try {
      const ecdhCurve = createEcdhCurve(
        myJwkPrivateKey.crv,
        this.#aes.randomBytes,
      );
      const myPrivateKey = ecdhCurve.toRawPrivateKey(myJwkPrivateKey);

      const {
        iv,
        ciphertext,
        tag,
        encryptedKey,
        aad,
        joseHeader,
        parsedProtected,
      } = validateFlattenedJwe(jwe);

      validateCrit({
        Err: JweInvalid,
        recognizedOption: options?.crit,
        protectedHeader: parsedProtected,
        joseHeader,
      });

      const alg = validateJweAlg(joseHeader.alg);
      const enc = validateJweEnc(joseHeader.enc);

      checkJweAlgAllowed(alg, options?.keyManagementAlgorithms);
      checkJweEncAllowed(enc, options?.contentEncryptionAlgorithms);

      const cek = await deriveDecryptionKeyWithMitigation({
        alg,
        enc,
        curve: ecdhCurve,
        myPrivateKey,
        encryptedKey,
        protectedHeader: parsedProtected,
      });

      const aesAad = encodeAesAad(jwe.protected, jwe.aad);

      const plaintext = await this.#aes.decrypt({
        enc,
        cek,
        ciphertext,
        iv,
        tag,
        aad: aesAad,
      });

      const result: FlattenedDecryptResult = {
        plaintext,
        protectedHeader: parsedProtected,
      };

      if (jwe.aad !== undefined) {
        result.additionalAuthenticatedData = aad;
      }

      if (jwe.unprotected !== undefined) {
        result.sharedUnprotectedHeader = jwe.unprotected;
      }

      if (jwe.header !== undefined) {
        result.unprotectedHeader = jwe.header;
      }

      return result;
    } catch (error) {
      console.error(error);
      throw new JweInvalid('Failed to decrypt JWE');
    }
  }
}
