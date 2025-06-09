import { CritOption, JoseHeaderParameters } from '@/jose/types';

/** Recognized JWE Key Management-related Header Parameters. */
export interface JweKeyManagementHeaderParameters {
  apu?: Uint8Array;
  apv?: Uint8Array;
}

export interface JweHeaderParameters extends JoseHeaderParameters {
  /**
   * JWE "alg" (Algorithm) Header Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210#jwe-alg Algorithm Key Requirements}
   */
  alg?: string;

  /**
   * JWE "enc" (Encryption Algorithm) Header Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210#jwe-alg Algorithm Key Requirements}
   */
  enc?: string;

  /** JWE "crit" (Critical) Header Parameter */
  crit?: string[];

  /** Any other JWE Header member. */
  [propName: string]: unknown;
}

/** JWE Encryption options. */
export interface EncryptOptions extends CritOption {}

/** JWE Decryption options. */
export interface DecryptOptions extends CritOption {
  /**
   * A list of accepted JWE "alg" (Algorithm) Header Parameter values. By default all "alg"
   * (Algorithm) Header Parameter values applicable for the used key/secret are allowed except for
   * all PBES2 Key Management Algorithms, these need to be explicitly allowed using this option.
   */
  keyManagementAlgorithms?: string[];

  /**
   * A list of accepted JWE "enc" (Encryption Algorithm) Header Parameter values. By default all
   * "enc" (Encryption Algorithm) values applicable for the used key/secret are allowed.
   */
  contentEncryptionAlgorithms?: string[];
}

/** Flattened JWE JSON Serialization Syntax token. */
export interface FlattenedJwe {
  /**
   * The "aad" member MUST be present and contain the value BASE64URL(JWE AAD)) when the JWE AAD
   * value is non-empty; otherwise, it MUST be absent. A JWE AAD value can be included to supply a
   * base64url-encoded value to be integrity protected but not encrypted.
   */
  aad?: string;

  /** The "ciphertext" member MUST be present and contain the value BASE64URL(JWE Ciphertext). */
  ciphertext: string;

  /**
   * The "encrypted_key" member MUST be present and contain the value BASE64URL(JWE Encrypted Key)
   * when the JWE Encrypted Key value is non-empty; otherwise, it MUST be absent.
   */
  encrypted_key?: string;

  /**
   * The "header" member MUST be present and contain the value JWE Per- Recipient Unprotected Header
   * when the JWE Per-Recipient Unprotected Header value is non-empty; otherwise, it MUST be absent.
   * This value is represented as an unencoded JSON object, rather than as a string. These Header
   * Parameter values are not integrity protected.
   */
  header?: JweHeaderParameters;

  /**
   * The "iv" member MUST be present and contain the value BASE64URL(JWE Initialization Vector) when
   * the JWE Initialization Vector value is non-empty; otherwise, it MUST be absent.
   */
  iv?: string;

  /**
   * The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWE Protected
   * Header)) when the JWE Protected Header value is non-empty; otherwise, it MUST be absent. These
   * Header Parameter values are integrity protected.
   */
  protected?: string;

  /**
   * The "tag" member MUST be present and contain the value BASE64URL(JWE Authentication Tag) when
   * the JWE Authentication Tag value is non-empty; otherwise, it MUST be absent.
   */
  tag?: string;

  /**
   * The "unprotected" member MUST be present and contain the value JWE Shared Unprotected Header
   * when the JWE Shared Unprotected Header value is non-empty; otherwise, it MUST be absent. This
   * value is represented as an unencoded JSON object, rather than as a string. These Header
   * Parameter values are not integrity protected.
   */
  unprotected?: JweHeaderParameters;
}
