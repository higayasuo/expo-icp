import { CritOption, JoseHeaderParameters } from '@/jose/types';
import { Jwk } from '@/jose/types';
import { Enc } from 'aes-universal';
import { NistCurveName } from 'noble-curves-extended';

/**
 * JWE Key Management Algorithm
 *
 * Currently only supports ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static)
 */
export type JweAlg = 'ECDH-ES';

/**
 * JWE Content Encryption Algorithm
 *
 * Represents the supported encryption algorithms for JWE content encryption
 *
 * @see {@link Enc} from 'aes-universal' for supported algorithms
 */
export type JweEnc = Enc;

export type JweCrv = NistCurveName;

/** Recognized JWE Key Management-related Header Parameters. */
export interface JweKeyManagementHeaderParameters {
  apu?: Uint8Array;
  apv?: Uint8Array;
}

export interface JweHeaderParameters extends JoseHeaderParameters {
  /**
   * JWE "alg" (Key Management Algorithm) Header Parameter
   * Identifies the cryptographic algorithm used to encrypt or determine the value of the CEK.
   *
   * @see {@link https://github.com/panva/jose/issues/210#jwe-alg Algorithm Key Requirements}
   */
  alg?: JweAlg;

  /**
   * JWE "enc" (Content Encryption Algorithm) Header Parameter
   * Identifies the content encryption algorithm used to perform authenticated encryption on the plaintext.
   *
   * @see {@link https://github.com/panva/jose/issues/210#jwe-alg Algorithm Key Requirements}
   */
  enc?: JweEnc;

  /** JWE "crit" (Critical) Header Parameter */
  crit?: string[];

  /**
   * JWE "apu" (Agreement PartyUInfo) Header Parameter
   * Used in key agreement algorithms to provide information about the producer of the key agreement.
   * The value is base64url encoded.
   */
  apu?: string;

  /**
   * JWE "apv" (Agreement PartyVInfo) Header Parameter
   * Used in key agreement algorithms to provide information about the recipient of the key agreement.
   * The value is base64url encoded.
   */
  apv?: string;

  /**
   * JWE "epk" (Ephemeral Public Key) Header Parameter
   * Used in key agreement algorithms to provide the ephemeral public key.
   * The value is a JSON Web Key object.
   */
  epk?: Jwk;

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

/** Flattened JWE JSON Serialization Syntax decryption result */
export interface FlattenedDecryptResult {
  /** JWE AAD. */
  additionalAuthenticatedData?: Uint8Array;

  /** Plaintext. */
  plaintext: Uint8Array;

  /** JWE Protected Header. */
  protectedHeader?: JweHeaderParameters;

  /** JWE Shared Unprotected Header. */
  sharedUnprotectedHeader?: JweHeaderParameters;

  /** JWE Per-Recipient Unprotected Header. */
  unprotectedHeader?: JweHeaderParameters;
}
