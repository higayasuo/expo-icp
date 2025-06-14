/**
 * Encrypting JSON Web Encryption (JWE) in Compact Serialization
 *
 * @module
 */

import {
  FlattenedEncryption,
  FlattenedEncryptionParams,
} from '../flattened/FlattenedEncryption';
import {
  CompactJweHeaderParameters,
  EncryptOptions,
  JweKeyManagementHeaderParameters,
} from '../types';

/**
 * Class for encrypting JSON Web Encryption (JWE) in Compact Serialization.
 */
export class CompactEncryption {
  #flattened: FlattenedEncryption;

  /**
   * Constructs a new CompactEncrypt instance.
   *
   * @param {FlattenedEncryptionParams} params - The parameters for flattened encryption.
   */
  constructor(params: FlattenedEncryptionParams) {
    this.#flattened = new FlattenedEncryption(params);
  }

  /**
   * Sets the JWE Protected Header on the CompactEncrypt object.
   *
   * @param {CompactJweHeaderParameters} protectedHeader - JWE Protected Header.
   * @returns {this} The current CompactEncrypt instance.
   */
  protectedHeader(protectedHeader: CompactJweHeaderParameters): this {
    this.#flattened.protectedHeader(protectedHeader);
    return this;
  }

  /**
   * Sets the JWE Key Management parameters to be used when encrypting.
   *
   * @param {JweKeyManagementHeaderParameters} parameters - JWE Key Management parameters.
   * @returns {this} The current CompactEncrypt instance.
   */
  keyManagementParameters(parameters: JweKeyManagementHeaderParameters): this {
    this.#flattened.keyManagementParameters(parameters);
    return this;
  }

  /**
   * Encrypts the given plaintext using the provided public key and options.
   *
   * @param {Uint8Array} plaintext - The plaintext to encrypt.
   * @param {Uint8Array} yourPublicKey - The public key to use for encryption.
   * @param {EncryptOptions} [options] - Optional encryption options.
   * @returns {Promise<string>} A promise that resolves to the JWE in compact serialization format.
   */
  async encrypt(
    plaintext: Uint8Array,
    yourPublicKey: Uint8Array,
    options?: EncryptOptions,
  ): Promise<string> {
    const jwe = await this.#flattened.encrypt(
      plaintext,
      yourPublicKey,
      options,
    );

    return [
      jwe.protected,
      jwe.encrypted_key,
      jwe.iv,
      jwe.ciphertext,
      jwe.tag,
    ].join('.');
  }
}
