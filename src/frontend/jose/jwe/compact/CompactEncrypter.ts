/**
 * Encrypting JSON Web Encryption (JWE) in Compact Serialization
 *
 * @module
 */

import { AesCipher } from 'aes-universal';
import { FlattenedEncrypter } from '../flattened/FlattenedEncrypter';
import { CompactJweHeaderParameters } from './types';
import {
  EncryptOptions,
  JweKeyManagementHeaderParameters,
} from '@/jose/jwe/types';
import { JwkPublicKey } from 'noble-curves-extended';

/**
 * Class representing the Compact Encrypter for JSON Web Encryption (JWE).
 */
export class CompactEncrypter {
  #flattened: FlattenedEncrypter;

  /**
   * Creates an instance of CompactEncrypter.
   *
   * @param {AesCipher} aes - An instance of AesCipher used for encryption operations.
   */
  constructor(aes: AesCipher) {
    this.#flattened = new FlattenedEncrypter(aes);
  }

  /**
   * Sets the JWE Protected Header.
   *
   * @param {CompactJweHeaderParameters} protectedHeader - JWE Protected Header.
   * @returns {this} The current instance for method chaining.
   */
  protectedHeader(protectedHeader: CompactJweHeaderParameters): this {
    this.#flattened.protectedHeader(protectedHeader);
    return this;
  }

  /**
   * Sets the JWE Key Management parameters.
   *
   * @param {JweKeyManagementHeaderParameters} parameters - JWE Key Management parameters.
   * @returns {this} The current instance for method chaining.
   */
  keyManagementParameters(parameters: JweKeyManagementHeaderParameters): this {
    this.#flattened.keyManagementParameters(parameters);
    return this;
  }

  /**
   * Encrypts the provided plaintext using the given JWK public key.
   *
   * @param {Uint8Array} plaintext - The plaintext to encrypt.
   * @param {JwkPublicKey} jwkPublicKey - The JWK public key for encryption.
   * @param {EncryptOptions} [options] - Optional encryption options.
   * @returns {Promise<string>} A promise that resolves to the encrypted JWE in compact serialization.
   */
  async encrypt(
    plaintext: Uint8Array,
    jwkPublicKey: JwkPublicKey,
    options?: EncryptOptions,
  ): Promise<string> {
    const flattenedJwe = await this.#flattened.encrypt(
      plaintext,
      jwkPublicKey,
      options,
    );

    const compactJwe = [
      flattenedJwe.protected,
      flattenedJwe.encrypted_key || '',
      flattenedJwe.iv,
      flattenedJwe.ciphertext,
      flattenedJwe.tag,
    ].join('.');

    return compactJwe;
  }
}
