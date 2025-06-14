/**
 * Decrypting JSON Web Encryption (JWE) in Flattened JSON Serialization
 *
 * @module
 */

import { JweInvalid } from '@/jose/errors/errors.js';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { validateCrit } from '@/jose/utils/validateCrit';
import { DecryptOptions, FlattenedDecryptResult, FlattenedJwe } from '../types';
import { validateFlattenedJwe } from './utils/validateFlattenedJwe';
import { validateJweAlg } from '../utils/validateJweAlg';
import { validateJweEnc } from '../utils/validateJweEnc';
import { checkJweAlgAllowed } from './utils/checkJweAlgAllowed';
import { checkJweEncAllowed } from './utils/checkJweEncAllowed';
import { NistCurve } from 'noble-curves-extended';
import { AesCipher } from 'aes-universal';
import { isUint8Array } from 'u8a-utils';
import { deriveDecryptionKeyWithMitigation } from './utils/deriveDecryptionKeyWithMitigation';
import { buildAesAad } from './utils/buildAesAad';

export type FlattenedDecryptionParams = {
  curve: NistCurve;
  aes: AesCipher;
};

export class FlattenedDecryption {
  #curve: NistCurve;
  #aes: AesCipher;

  constructor({ curve, aes }: FlattenedDecryptionParams) {
    this.#curve = curve;
    this.#aes = aes;
  }

  async decrypt(
    jwe: FlattenedJwe,
    myPrivateKey: Uint8Array,
    options?: DecryptOptions,
  ): Promise<FlattenedDecryptResult> {
    if (!isPlainObject(jwe)) {
      throw new JweInvalid('Flattened JWE must be a plain object');
    }

    if (!this.#curve.utils.isValidPrivateKey(myPrivateKey)) {
      throw new JweInvalid('myPrivateKey is invalid');
    }

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
      curve: this.#curve,
      myPrivateKey,
      encryptedKey,
      protectedHeader: parsedProtected,
    });

    const aesAad = buildAesAad(jwe.protected, jwe.aad);

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
  }
}
