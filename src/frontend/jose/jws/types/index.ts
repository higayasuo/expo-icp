import { CritOption, JoseHeaderParameters } from '@/jose/types';
import { JWS_ALGS } from '../constants';

/**
 * JSON Web Signature (JWS) Algorithm
 *
 * Represents the supported algorithms for JWS operations.
 */
export type JwsAlg = (typeof JWS_ALGS)[number];

/** Recognized JWS Header Parameters, any other Header Members may also be present. */
export interface JwsHeaderParameters extends JoseHeaderParameters {
  /**
   * JWS "alg" (Algorithm) Header Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}
   */
  alg?: JwsAlg;

  /**
   * This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing
   * Input computation as per {@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}.
   */
  b64?: boolean;

  /** JWS "crit" (Critical) Header Parameter */
  crit?: string[];

  /** Any other JWS Header member. */
  [propName: string]: unknown;
}

/** JWS Signing options. */
export interface SignOptions extends CritOption {}

/** JWS Verification options. */
export interface VerifyOptions extends CritOption {
  /**
   * A list of accepted JWS "alg" (Algorithm) Header Parameter values. By default all "alg"
   * (Algorithm) values applicable for the used key/secret are allowed.
   *
   * > [!NOTE]\
   * > Unsecured JWTs (`{ "alg": "none" }`) are never accepted by this API.
   */
  algorithms?: string[];
}
