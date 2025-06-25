import { CritOption, JoseHeaderParameters } from '@/jose/types';

/** Recognized JWS Header Parameters, any other Header Members may also be present. */
export interface JwsHeaderParameters extends JoseHeaderParameters {
  /**
   * JWS "alg" (Algorithm) Header Parameter
   *
   * @see {@link https://github.com/panva/jose/issues/210#jws-alg Algorithm Key Requirements}
   */
  alg?: string;

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

/**
 * Flattened JWS definition for verify function inputs, allows payload as {@link !Uint8Array} for
 * detached signature validation.
 */
export interface FlattenedJwsInput {
  /**
   * The "header" member MUST be present and contain the value JWS Unprotected Header when the JWS
   * Unprotected Header value is non- empty; otherwise, it MUST be absent. This value is represented
   * as an unencoded JSON object, rather than as a string. These Header Parameter values are not
   * integrity protected.
   */
  header?: JwsHeaderParameters;

  /**
   * The "payload" member MUST be present and contain the value BASE64URL(JWS Payload). When RFC7797
   * "b64": false is used the value passed may also be a {@link !Uint8Array}.
   */
  payload: string | Uint8Array;

  /**
   * The "protected" member MUST be present and contain the value BASE64URL(UTF8(JWS Protected
   * Header)) when the JWS Protected Header value is non-empty; otherwise, it MUST be absent. These
   * Header Parameter values are integrity protected.
   */
  protected?: string;

  /** The "signature" member MUST be present and contain the value BASE64URL(JWS Signature). */
  signature: string;
}

/**
 * General JWS definition for verify function inputs, allows payload as {@link !Uint8Array} for
 * detached signature validation.
 */
export interface GeneralJWSInput {
  /**
   * The "payload" member MUST be present and contain the value BASE64URL(JWS Payload). When when
   * JWS Unencoded Payload ({@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}) "b64": false is
   * used the value passed may also be a {@link !Uint8Array}.
   */
  payload: string | Uint8Array;

  /**
   * The "signatures" member value MUST be an array of JSON objects. Each object represents a
   * signature or MAC over the JWS Payload and the JWS Protected Header.
   */
  signatures: Omit<FlattenedJwsInput, 'payload'>[];
}

/**
 * Flattened JWS JSON Serialization Syntax token. Payload is returned as an empty string when JWS
 * Unencoded Payload ({@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}) is used.
 */
export interface FlattenedJws extends FlattenedJwsInput {
  payload: string;
}

/** JWS Signing options. */
export interface SignOptions extends CritOption {}
