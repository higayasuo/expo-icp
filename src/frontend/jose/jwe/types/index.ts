import { CritOption, JoseHeaderParameters } from '@/jose/types';
import { Jwk } from '@/jose/types';
import { Enc } from 'aes-universal';
import { EcdhCurveName } from 'noble-curves-extended';

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

/**
 * JWE Curve Name
 *
 * Represents the supported elliptic curve names for JWE operations.
 */
export type JweCrv = EcdhCurveName;

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
