/**
 * Encrypting JSON Web Encryption (JWE) in Flattened JSON Serialization
 */

import { manageEncryptKey } from '../key-management/manageEncryptKey';
import { hasNoDuplicateKeys } from '../utils/hasNoDuplicateKeys';
import { validateCrit } from '../../utils/validateCrit';
import {
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
  EncryptOptions,
  FlattenedJwe,
} from '../types';
import { JweInvalid, JoseNotSupported } from '@/jose/errors/errors';
import { NistCurve } from 'noble-curves-extended';
import { AesCipher, isEnc } from 'aes-universal';
import { toB64U, concatUint8Arrays } from 'u8a-utils';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

type FlattenedEncryptParams = {
  curve: NistCurve;
  aes: AesCipher;
  plaintext: Uint8Array;
};

export class FlattenedEncrypt {
  #curve: NistCurve;

  #aes: AesCipher;

  #plaintext: Uint8Array;

  #protectedHeader!: JweHeaderParameters | undefined;

  #sharedUnprotectedHeader!: JweHeaderParameters | undefined;

  #unprotectedHeader!: JweHeaderParameters | undefined;

  #aad!: Uint8Array | undefined;

  #keyManagementParameters!: JweKeyManagementHeaderParameters;

  /**
   * {@link FlattenedEncrypt} constructor
   *
   * @param plaintext Binary representation of the plaintext to encrypt.
   */
  constructor({ curve, aes, plaintext }: FlattenedEncryptParams) {
    if (!(plaintext instanceof Uint8Array)) {
      throw new TypeError('plaintext must be an instance of Uint8Array');
    }
    this.#plaintext = plaintext;
    this.#curve = curve;
    this.#aes = aes;
  }

  /**
   * Sets the JWE Key Management parameters to be used when encrypting. Use of this is method is
   * really only needed for ECDH based algorithms when utilizing the Agreement PartyUInfo or
   * Agreement PartyVInfo parameters. Other parameters will always be randomly generated when needed
   * and missing.
   *
   * @param parameters JWE Key Management parameters.
   */
  keyManagementParameters(parameters: JweKeyManagementHeaderParameters): this {
    if (this.#keyManagementParameters) {
      throw new TypeError('keyManagementParameters can only be called once');
    }
    this.#keyManagementParameters = parameters;
    return this;
  }

  /**
   * Sets the JWE Protected Header on the FlattenedEncrypt object.
   *
   * @param protectedHeader JWE Protected Header.
   */
  protectedHeader(protectedHeader: JweHeaderParameters): this {
    if (this.#protectedHeader) {
      throw new TypeError('protectedHeader can only be called once');
    }
    this.#protectedHeader = protectedHeader;
    return this;
  }

  /**
   * Sets the JWE Shared Unprotected Header on the FlattenedEncrypt object.
   *
   * @param sharedUnprotectedHeader JWE Shared Unprotected Header.
   */
  sharedUnprotectedHeader(sharedUnprotectedHeader: JweHeaderParameters): this {
    if (this.#sharedUnprotectedHeader) {
      throw new TypeError('sharedUnprotectedHeader can only be called once');
    }
    this.#sharedUnprotectedHeader = sharedUnprotectedHeader;
    return this;
  }

  /**
   * Sets the JWE Per-Recipient Unprotected Header on the FlattenedEncrypt object.
   *
   * @param unprotectedHeader JWE Per-Recipient Unprotected Header.
   */
  unprotectedHeader(unprotectedHeader: JweHeaderParameters): this {
    if (this.#unprotectedHeader) {
      throw new TypeError('unprotectedHeader can only be called once');
    }
    this.#unprotectedHeader = unprotectedHeader;
    return this;
  }

  /**
   * Sets the Additional Authenticated Data on the FlattenedEncrypt object.
   *
   * @param aad Additional Authenticated Data.
   */
  additionalAuthenticatedData(aad: Uint8Array): this {
    this.#aad = aad;
    return this;
  }

  async encrypt(
    yourPublicKey: Uint8Array,
    options?: EncryptOptions,
  ): Promise<FlattenedJwe> {
    if (
      !this.#protectedHeader &&
      !this.#unprotectedHeader &&
      !this.#sharedUnprotectedHeader
    ) {
      throw new JweInvalid(
        'either setProtectedHeader, setUnprotectedHeader, or sharedUnprotectedHeader must be called before #encrypt()',
      );
    }

    if (
      !hasNoDuplicateKeys(
        this.#protectedHeader,
        this.#unprotectedHeader,
        this.#sharedUnprotectedHeader,
      )
    ) {
      throw new JweInvalid(
        'JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint',
      );
    }

    const joseHeader: JweHeaderParameters = {
      ...this.#protectedHeader,
      ...this.#unprotectedHeader,
      ...this.#sharedUnprotectedHeader,
    };

    validateCrit({
      Err: JweInvalid,
      recognizedOption: options?.crit,
      protectedHeader: this.#protectedHeader,
      joseHeader,
    });

    if (joseHeader.zip !== undefined) {
      throw new JoseNotSupported(
        'JWE "zip" (Compression Algorithm) Header Parameter is not supported.',
      );
    }

    if (!this.#protectedHeader) {
      throw new JweInvalid('JWE Protected Header Parameter missing');
    }

    const { alg, enc } = this.#protectedHeader;

    if (typeof alg !== 'string' || !alg) {
      throw new JweInvalid(
        'JWE "alg" (Algorithm) Header Parameter missing or invalid',
      );
    }

    if (typeof enc !== 'string' || !isEnc(enc)) {
      throw new JweInvalid(
        'JWE "enc" (Encryption Algorithm) Header Parameter missing or invalid',
      );
    }

    const { cek, encryptedKey, parameters } = manageEncryptKey({
      alg,
      enc,
      curve: this.#curve,
      yourPublicKey,
      providedParameters: this.#keyManagementParameters,
    });

    if (parameters) {
      if (!this.#protectedHeader) {
        this.protectedHeader(parameters);
      } else {
        this.#protectedHeader = { ...this.#protectedHeader, ...parameters };
      }
    }

    let additionalData: Uint8Array;
    let protectedHeader: Uint8Array;
    let aadMember: string | undefined;
    if (this.#protectedHeader) {
      protectedHeader = encoder.encode(
        toB64U(encoder.encode(JSON.stringify(this.#protectedHeader))),
      );
    } else {
      protectedHeader = encoder.encode('');
    }

    if (this.#aad) {
      aadMember = toB64U(this.#aad);
      additionalData = concatUint8Arrays(
        protectedHeader,
        encoder.encode('.'),
        encoder.encode(aadMember),
      );
    } else {
      additionalData = protectedHeader;
    }

    const { ciphertext, tag, iv } = await this.#aes.encrypt({
      enc,
      plaintext: this.#plaintext,
      cek,
      aad: additionalData,
    });

    const jwe: FlattenedJwe = {
      ciphertext: toB64U(ciphertext),
    };

    if (iv) {
      jwe.iv = toB64U(iv);
    }

    if (tag) {
      jwe.tag = toB64U(tag);
    }

    if (encryptedKey) {
      jwe.encrypted_key = toB64U(encryptedKey);
    }

    if (aadMember) {
      jwe.aad = aadMember;
    }

    if (this.#protectedHeader) {
      jwe.protected = decoder.decode(protectedHeader);
    }

    if (this.#sharedUnprotectedHeader) {
      jwe.unprotected = this.#sharedUnprotectedHeader;
    }

    if (this.#unprotectedHeader) {
      jwe.header = this.#unprotectedHeader;
    }

    return jwe;
  }
}
