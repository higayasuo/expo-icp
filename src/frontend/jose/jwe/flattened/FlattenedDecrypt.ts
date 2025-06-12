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

const encoder = new TextEncoder();

type FlattenedDecryptParams = {
  curve: NistCurve;
  aes: AesCipher;
};

export class FlattenedDecrypt {
  #curve: NistCurve;
  #aes: AesCipher;

  constructor({ curve, aes }: FlattenedDecryptParams) {
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

    let cek: Uint8Array;
    try {
      cek = await deriveDecryptionKey({
        alg,
        curve: this.#curve,
        myPrivateKey,
        encryptedKey,
        protectedHeader: parsedProtected,
      });
    } catch (err) {
      console.error(err);

      // https://www.rfc-editor.org/rfc/rfc7516#section-11.5
      // To mitigate the attacks described in RFC 3218, the
      // recipient MUST NOT distinguish between format, padding, and length
      // errors of encrypted keys.  It is strongly recommended, in the event
      // of receiving an improperly formatted key, that the recipient
      // substitute a randomly generated CEK and proceed to the next step, to
      // mitigate timing attacks.

      // Add random delay to mitigate timing attacks
      await sleep(Math.random() * 500);
      const cekBitLength = cekBitLengthByEnc(enc);
      cek = this.#curve.randomBytes(cekBitLength >> 3);
    }

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
