/**
 * Decrypting JSON Web Encryption (JWE) in Flattened JSON Serialization
 *
 * @module
 */

import { JoseNotSupported, JweInvalid } from '@/jose/errors/errors.js';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { deriveDecryptionKey } from '../key-management/deriveDecryptionKey';
import { concatUint8Arrays } from 'u8a-utils';
import { validateCrit } from '@/jose/utils/validateCrit';
import { DecryptOptions, FlattenedDecryptResult, FlattenedJwe } from '../types';
import { validateFlattenedJwe } from './utils/validateFlattenedJwe';
import { validateJweAlg } from '../utils/validateJweAlg';
import { validateJweEnc } from '../utils/validateJweEnc';
import { checkJweAlgAllowed } from './utils/checkJweAlgAllowed';
import { checkJweEncAllowed } from './utils/checkJweEncAllowed';
import { NistCurve } from 'noble-curves-extended';
import { AesCipher } from 'aes-universal';
import { ensureUint8Array, isUint8Array } from 'u8a-utils';
import { sleep } from '@/jose/utils/sleep';
import { cekBitLengthByEnc } from '../utils/cekBitLengthByEnc';
import { generateMitigatedCek } from './utils/generateMitigatedCek';
import { deriveDecryptionKeyWithMitigation } from './utils/deriveDecryptionKeyWithMitigation';

const encoder = new TextEncoder();

type FlattenedDecryptionParams = {
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

    if (!isUint8Array(myPrivateKey)) {
      throw new TypeError('myPrivateKey must be an Uint8Array');
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

    const protectedHeader: Uint8Array = encoder.encode(jwe.protected ?? '');
    let additionalData: Uint8Array;

    if (jwe.aad !== undefined) {
      additionalData = concat(
        protectedHeader,
        encoder.encode('.'),
        encoder.encode(jwe.aad),
      );
    } else {
      additionalData = protectedHeader;
    }

    const plaintext = await decrypt(
      enc,
      cek,
      ciphertext,
      iv,
      tag,
      additionalData,
    );

    const result: FlattenedDecryptResult = { plaintext };

    if (jwe.protected !== undefined) {
      result.protectedHeader = parsedProtected;
    }

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
