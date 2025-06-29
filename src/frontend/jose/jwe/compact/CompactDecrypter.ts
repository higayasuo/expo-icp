/**
 * Decrypting JSON Web Encryption (JWE) in Compact Serialization
 *
 * @module
 */

import { FlattenedDecrypter } from '@/jose/jwe/flattened/FlattenedDecrypter';
import { JweInvalid } from '@/jose/errors/errors';
import { DecryptOptions } from '@/jose/jwe/types';
import { FlattenedJwe } from '@/jose/jwe/flattened/types';
import { AesCipher } from 'aes-universal';
import { JwkPrivateKey } from 'noble-curves-extended';
import { CompactDecryptResult, CompactJweHeaderParameters } from './types';

/**
 * Class representing the Compact Decrypter for JSON Web Encryption (JWE).
 */
export class CompactDecrypter {
  #flattened: FlattenedDecrypter;

  /**
   * Creates an instance of CompactDecrypter.
   *
   * @param {AesCipher} aes - An instance of AesCipher used for decryption operations.
   */
  constructor(aes: AesCipher) {
    this.#flattened = new FlattenedDecrypter(aes);
  }

  /**
   * Decrypts a Compact JWE.
   *
   * @param {string} compactJwe - The Compact JWE string to decrypt.
   * @param {JwkPrivateKey} myJwkPrivateKey - The JWK private key used for decryption.
   * @param {DecryptOptions} [options] - Optional decryption options.
   * @returns {Promise<{plaintext: Uint8Array, protectedHeader: CompactJweHeaderParameters}>} A promise that resolves to the decryption result.
   * @throws {JweInvalid} If any required parameter is missing or invalid, or if decryption fails.
   */
  async decrypt(
    compactJwe: string,
    myJwkPrivateKey: JwkPrivateKey,
    options?: DecryptOptions,
  ): Promise<CompactDecryptResult> {
    if (typeof compactJwe !== 'string') {
      throw new JweInvalid('Compact JWE must be a string');
    }

    const {
      0: protectedHeader,
      1: encrypted_key,
      2: iv,
      3: ciphertext,
      4: tag,
      length,
    } = compactJwe.split('.');

    if (length !== 5) {
      throw new JweInvalid('Invalid Compact JWE: must have 5 parts');
    }

    if (!protectedHeader) {
      throw new JweInvalid('Invalid Compact JWE: protected header is missing');
    }

    if (!iv) {
      throw new JweInvalid('Invalid Compact JWE: iv is missing');
    }

    if (!ciphertext) {
      throw new JweInvalid('Invalid Compact JWE: ciphertext is missing');
    }

    if (!tag) {
      throw new JweInvalid('Invalid Compact JWE: tag is missing');
    }

    const jwe: FlattenedJwe = {
      protected: protectedHeader,
      encrypted_key,
      iv,
      ciphertext,
      tag,
    };

    const decrypted = await this.#flattened.decrypt(
      jwe,
      myJwkPrivateKey,
      options,
    );

    const result = {
      plaintext: decrypted.plaintext,
      protectedHeader: decrypted.protectedHeader as CompactJweHeaderParameters,
    };

    return result;
  }
}
