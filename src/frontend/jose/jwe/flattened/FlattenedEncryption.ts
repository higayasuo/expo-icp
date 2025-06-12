/**
 * Encrypting JSON Web Encryption (JWE) in Flattened JSON Serialization
 */

import { deriveEncryptionKey } from '../key-management/deriveEncryptionKey';
import { validateCrit } from '../../utils/validateCrit';
import {
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
  EncryptOptions,
  FlattenedJwe,
  JweAlg,
  JweEnc,
} from '../types';
import { JweInvalid } from '@/jose/errors/errors';
import { NistCurve } from 'noble-curves-extended';
import { AesCipher } from 'aes-universal';
import { encodeBase64Url, ensureUint8Array, isUint8Array } from 'u8a-utils';
import { validateJweAlg } from '../utils/validateJweAlg';
import { validateJweEnc } from '../utils/validateJweEnc';
import { buildJoseHeader } from './utils/buildJoseHeader';
import { buildBase64UrlJweHeader } from './utils/buildBase64UrlJweHeader';
import { buildAesAad } from './utils/buildAesAad';

const encoder = new TextEncoder();

type FlattenedEncryptionParams = {
  curve: NistCurve;
  aes: AesCipher;
};

export class FlattenedEncryption {
  #curve: NistCurve;
  #aes: AesCipher;
  #protectedHeader!: JweHeaderParameters | undefined;
  #sharedUnprotectedHeader!: JweHeaderParameters | undefined;
  #unprotectedHeader!: JweHeaderParameters | undefined;
  #aad!: Uint8Array | undefined;
  #keyManagementParameters!: JweKeyManagementHeaderParameters;

  /**
   * {@link FlattenedEncryption} constructor
   *
   * @param curve The curve to use for key derivation
   * @param aes The AES cipher to use for encryption
   */
  constructor({ curve, aes }: FlattenedEncryptionParams) {
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
   * Sets the JWE Protected Header on the FlattenedEncryption object.
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
   * Sets the JWE Shared Unprotected Header on the FlattenedEncryption object.
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
   * Sets the JWE Per-Recipient Unprotected Header on the FlattenedEncryption object.
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
   * Sets the Additional Authenticated Data on the FlattenedEncryption object.
   *
   * @param aad Additional Authenticated Data.
   */
  additionalAuthenticatedData(aad: Uint8Array): this {
    this.#aad = aad;
    return this;
  }

  async encrypt(
    plaintext: Uint8Array,
    yourPublicKey: Uint8Array,
    options?: EncryptOptions,
  ): Promise<FlattenedJwe> {
    if (!isUint8Array(plaintext)) {
      throw new TypeError('plaintext must be an Uint8Array');
    }
    const validatedPlaintext = ensureUint8Array(plaintext);

    if (!this.#protectedHeader) {
      throw new JweInvalid('JWE Protected Header is missing');
    }

    const joseHeader = buildJoseHeader({
      protectedHeader: this.#protectedHeader,
      sharedUnprotectedHeader: this.#sharedUnprotectedHeader,
      unprotectedHeader: this.#unprotectedHeader,
    });

    validateCrit({
      Err: JweInvalid,
      recognizedOption: options?.crit,
      protectedHeader: this.#protectedHeader,
      joseHeader,
    });

    const alg = validateJweAlg(this.#protectedHeader.alg);
    const enc = validateJweEnc(this.#protectedHeader.enc);

    const { cek, encryptedKey, parameters } = deriveEncryptionKey({
      alg,
      enc,
      curve: this.#curve,
      yourPublicKey,
      providedParameters: this.#keyManagementParameters,
    });

    this.updateProtectedHeader(parameters);
    const protectedHeaderB64U = buildBase64UrlJweHeader(this.#protectedHeader);
    const aadB64U = this.#aad ? encodeBase64Url(this.#aad) : undefined;
    const aad = buildAesAad(protectedHeaderB64U, aadB64U);

    const { ciphertext, tag, iv } = await this.#aes.encrypt({
      enc,
      plaintext: validatedPlaintext,
      cek,
      aad,
    });

    const jwe: FlattenedJwe = {
      ciphertext: encodeBase64Url(ciphertext),
    };

    if (iv) {
      jwe.iv = encodeBase64Url(iv);
    }

    if (tag) {
      jwe.tag = encodeBase64Url(tag);
    }

    if (encryptedKey) {
      jwe.encrypted_key = encodeBase64Url(encryptedKey);
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

  updateProtectedHeader(parameters: JweHeaderParameters | undefined) {
    if (parameters) {
      if (!this.#protectedHeader) {
        this.protectedHeader(parameters);
      } else {
        this.#protectedHeader = { ...this.#protectedHeader, ...parameters };
      }
    }
  }
}
