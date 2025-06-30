import { JwsHeaderParameters } from '@/jose/jws/types';

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
  protected: string;

  /** The "signature" member MUST be present and contain the value BASE64URL(JWS Signature). */
  signature: string;
}

/**
 * Flattened JWS JSON Serialization Syntax token. Payload is returned as an empty string when JWS
 * Unencoded Payload ({@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}) is used.
 */
export interface FlattenedJws extends FlattenedJwsInput {
  payload: string;
}

/** Flattened JWS JSON Serialization Syntax verification result */
export interface FlattenedVerifyResult {
  /** JWS Payload. */
  payload: Uint8Array;

  /** JWS Protected Header. */
  protectedHeader?: JwsHeaderParameters;

  /** JWS Unprotected Header. */
  unprotectedHeader?: JwsHeaderParameters;
}
