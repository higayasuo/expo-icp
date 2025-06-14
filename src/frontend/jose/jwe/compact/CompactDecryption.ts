/**
 * Decrypting JSON Web Encryption (JWE) in Compact Serialization
 *
 * @module
 */

import {
  FlattenedDecryption,
  FlattenedDecryptionParams,
} from '../flattened/FlattenedDecryption';
import { JweInvalid } from '@/jose/errors/errors';
import { DecryptOptions, FlattenedJwe } from '../types';

export class CompactDecryption {
  #flattened: FlattenedDecryption;

  constructor(params: FlattenedDecryptionParams) {
    this.#flattened = new FlattenedDecryption(params);
  }

  async decrypt(
    compactJwe: string,
    myPrivateKey: Uint8Array,
    options?: DecryptOptions,
  ) {
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

    const decrypted = await this.#flattened.decrypt(jwe, myPrivateKey, options);

    const result = {
      plaintext: decrypted.plaintext,
      protectedHeader: decrypted.protectedHeader!,
    };

    return result;
  }
}
