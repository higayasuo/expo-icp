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
  JweAlg,
  JweEnc,
} from '../types';
import { JweInvalid, JoseNotSupported } from '@/jose/errors/errors';
import { NistCurve } from 'noble-curves-extended';
import { AesCipher } from 'aes-universal';
import { toB64U, ensureUint8Array, isUint8Array } from 'u8a-utils';
import { validateJweAlg } from '../utils/validateJweAlg';
import { validateJweEnc } from '../utils/validateJweEnc';

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
    if (!isUint8Array(plaintext)) {
      throw new TypeError('plaintext must be an Uint8Array');
    }
    this.#plaintext = ensureUint8Array(plaintext);
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
    const joseHeader = this.buildJoseHeader();

    validateCrit({
      Err: JweInvalid,
      recognizedOption: options?.crit,
      protectedHeader: this.#protectedHeader,
      joseHeader,
    });

    const { alg, enc } = this.getValidatedAlgAndEnc();

    const { cek, encryptedKey, parameters } = manageEncryptKey({
      alg,
      enc,
      curve: this.#curve,
      yourPublicKey,
      providedParameters: this.#keyManagementParameters,
    });

    this.updateProtectedHeader(parameters);
    const protectedHeaderB64U = this.buildProtectedHeaderB64U();
    const aadB64U = this.buildAadB64U(protectedHeaderB64U);
    const aad = encoder.encode(aadB64U);

    const { ciphertext, tag, iv } = await this.#aes.encrypt({
      enc,
      plaintext: this.#plaintext,
      cek,
      aad,
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

    if (this.#aad) {
      jwe.aad = aadB64U;
    }

    if (this.#protectedHeader) {
      jwe.protected = protectedHeaderB64U;
    }

    if (this.#sharedUnprotectedHeader) {
      jwe.unprotected = this.#sharedUnprotectedHeader;
    }

    if (this.#unprotectedHeader) {
      jwe.header = this.#unprotectedHeader;
    }

    return jwe;
  }

  verifyHeaders(): void {
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
  }

  buildJoseHeader(): JweHeaderParameters {
    this.verifyHeaders();

    const joseHeader: JweHeaderParameters = {
      ...this.#protectedHeader,
      ...this.#unprotectedHeader,
      ...this.#sharedUnprotectedHeader,
    };

    if (joseHeader.zip !== undefined) {
      throw new JoseNotSupported(
        'JWE "zip" (Compression Algorithm) Header Parameter is not supported.',
      );
    }

    return joseHeader;
  }

  getValidatedAlgAndEnc(): { alg: JweAlg; enc: JweEnc } {
    if (!this.#protectedHeader) {
      throw new JweInvalid('JWE Protected Header Parameter missing');
    }

    const alg = validateJweAlg(this.#protectedHeader.alg);
    const enc = validateJweEnc(this.#protectedHeader.enc);

    return { alg, enc };
  }

  updateProtectedHeader(parameters: JweHeaderParameters | undefined) {
    if (parameters) {
      if (!this.#protectedHeader) {
        this.protectedHeader(parameters);
      } else {
        this.#protectedHeader = { ...this.#protectedHeader, ...parameters };
      }
    }
  }

  buildProtectedHeaderB64U(): string {
    if (this.#protectedHeader) {
      return toB64U(encoder.encode(JSON.stringify(this.#protectedHeader)));
    }

    // RFC 7516: Return an empty string if the Protected Header is not present
    return '';
  }

  buildAadB64U(protectedHeaderB64U: string): string {
    if (this.#aad) {
      return `${protectedHeaderB64U}.${toB64U(this.#aad)}`;
    }

    return protectedHeaderB64U;
  }
}
