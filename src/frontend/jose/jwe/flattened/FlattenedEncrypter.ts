/**
 * Encrypting JSON Web Encryption (JWE) in Flattened JSON Serialization
 */

import { deriveEncryptionKey } from '@/jose/jwe/key-management/deriveEncryptionKey';
import { validateCrit } from '@/jose/utils/validateCrit';
import {
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
  EncryptOptions,
} from '@/jose/jwe/types';
import { FlattenedJwe } from './types';
import { JweInvalid } from '@/jose/errors/errors';
import { AesCipher } from 'aes-universal';
import { encodeBase64Url, ensureUint8Array, isUint8Array } from 'u8a-utils';
import { validateJweAlg } from '@/jose/jwe/utils/validateJweAlg';
import { validateJweEnc } from '@/jose/jwe/utils/validateJweEnc';
import { mergeJweHeaders } from './utils/mergeJweHeaders';
import { encodeBase64UrlHeader } from '@/jose/utils/encodeBase64UrlHeader';
import { encodeAesAad } from './utils/encodeAesAad';
import { JwkPublicKey, createEcdhCurve } from 'noble-curves-extended';
import { isPlainObject } from '@/jose/utils/isPlainObject';

/**
 * Class representing the Flattened Encrypter for JSON Web Encryption (JWE).
 */
export class FlattenedEncrypter {
  #aes: AesCipher;
  #protectedHeader!: JweHeaderParameters | undefined;
  #sharedUnprotectedHeader!: JweHeaderParameters | undefined;
  #unprotectedHeader!: JweHeaderParameters | undefined;
  #aad!: Uint8Array | undefined;
  #keyManagementParameters!: JweKeyManagementHeaderParameters;

  /**
   * Creates an instance of FlattenedEncrypter.
   *
   * @param {AesCipher} aes - An instance of AesCipher used for encryption operations.
   */
  constructor(aes: AesCipher) {
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
  keyManagementParameters = (
    parameters: JweKeyManagementHeaderParameters,
  ): this => {
    if (this.#keyManagementParameters) {
      throw new JweInvalid('keyManagementParameters can only be called once');
    }
    this.#keyManagementParameters = parameters;
    return this;
  };

  /**
   * Sets the JWE Protected Header.
   *
   * @param protectedHeader JWE Protected Header.
   */
  protectedHeader = (protectedHeader: JweHeaderParameters): this => {
    if (this.#protectedHeader) {
      throw new JweInvalid('protectedHeader can only be called once');
    }
    this.#protectedHeader = protectedHeader;
    return this;
  };

  /**
   * Sets the JWE Shared Unprotected Header.
   *
   * @param sharedUnprotectedHeader JWE Shared Unprotected Header.
   */
  sharedUnprotectedHeader = (
    sharedUnprotectedHeader: JweHeaderParameters,
  ): this => {
    if (this.#sharedUnprotectedHeader) {
      throw new JweInvalid('sharedUnprotectedHeader can only be called once');
    }
    this.#sharedUnprotectedHeader = sharedUnprotectedHeader;
    return this;
  };

  /**
   * Sets the JWE Per-Recipient Unprotected Header.
   *
   * @param unprotectedHeader JWE Per-Recipient Unprotected Header.
   */
  unprotectedHeader = (unprotectedHeader: JweHeaderParameters): this => {
    if (this.#unprotectedHeader) {
      throw new JweInvalid('unprotectedHeader can only be called once');
    }
    this.#unprotectedHeader = unprotectedHeader;
    return this;
  };

  /**
   * Sets the Additional Authenticated Data.
   *
   * @param aad Additional Authenticated Data.
   */
  additionalAuthenticatedData = (aad: Uint8Array): this => {
    this.#aad = aad;
    return this;
  };

  encrypt = async (
    plaintext: Uint8Array,
    yourJwkPublicKey: JwkPublicKey,
    options?: EncryptOptions,
  ): Promise<FlattenedJwe> => {
    if (!plaintext) {
      throw new JweInvalid('plaintext is missing');
    }

    if (!isUint8Array(plaintext)) {
      throw new JweInvalid('plaintext must be a Uint8Array');
    }

    if (!yourJwkPublicKey) {
      throw new JweInvalid('yourJwkPublicKey is missing');
    }

    if (!isPlainObject(yourJwkPublicKey)) {
      throw new JweInvalid('yourJwkPublicKey must be a plain object');
    }

    if (!yourJwkPublicKey.crv) {
      throw new JweInvalid('yourJwkPublicKey.crv is missing');
    }

    try {
      plaintext = ensureUint8Array(plaintext);

      const ecdhCurve = createEcdhCurve(
        yourJwkPublicKey.crv,
        this.#aes.randomBytes,
      );

      const yourPublicKey = ecdhCurve.toRawPublicKey(yourJwkPublicKey);

      const joseHeader = mergeJweHeaders({
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

      const alg = validateJweAlg(this.#protectedHeader?.alg);
      const enc = validateJweEnc(this.#protectedHeader?.enc);

      const { cek, encryptedKey, parameters } = deriveEncryptionKey({
        alg,
        enc,
        curve: ecdhCurve,
        yourPublicKey,
        providedParameters: this.#keyManagementParameters,
      });

      this.updateProtectedHeader(parameters);
      const protectedHeaderB64U = encodeBase64UrlHeader(this.#protectedHeader);
      const aadB64U = this.#aad ? encodeBase64Url(this.#aad) : undefined;
      const aad = encodeAesAad(protectedHeaderB64U, aadB64U);

      const { ciphertext, tag, iv } = await this.#aes.encrypt({
        enc,
        plaintext,
        cek,
        aad,
      });

      const jwe: FlattenedJwe = {
        ciphertext: encodeBase64Url(ciphertext),
        iv: encodeBase64Url(iv),
        tag: encodeBase64Url(tag),
        protected: protectedHeaderB64U,
      };

      if (encryptedKey) {
        jwe.encrypted_key = encodeBase64Url(encryptedKey);
      }

      if (this.#aad) {
        jwe.aad = aadB64U;
      }

      if (this.#sharedUnprotectedHeader) {
        jwe.unprotected = this.#sharedUnprotectedHeader;
      }

      if (this.#unprotectedHeader) {
        jwe.header = this.#unprotectedHeader;
      }

      return jwe;
    } catch (error) {
      console.error(error);
      throw new JweInvalid('Failed to encrypt plaintext');
    }
  };

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
