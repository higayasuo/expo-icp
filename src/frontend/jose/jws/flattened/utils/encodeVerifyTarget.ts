import { concatUint8Arrays, decodeBase64Url, isUint8Array } from 'u8a-utils';

const encoder = new TextEncoder();

/**
 * Parameters for encoding a JWS verification target
 */
type EncodeVerifyTargetParams = {
  /** Base64URL-encoded protected header */
  protectedHeaderB64U: string;
  /** Payload as either a Uint8Array or string */
  payload: Uint8Array | string;
  /** Whether the payload is base64url-encoded (b64=true) or not (b64=false) */
  b64: boolean;
};

/**
 * Result of encoding a JWS verification target
 */
type EncodeVerifyTargetResult = {
  /** The encoded verification target (protected_header.payload) */
  verifyTarget: Uint8Array;
  /** The decoded payload as Uint8Array */
  payload: Uint8Array;
};

/**
 * Encodes a JWS verification target according to RFC 7515
 *
 * This function creates the verification target used in JWS signature verification
 * and resolves the contradiction present in some JOSE implementations.
 *
 * The verification target construction follows these rules:
 * - When b64=true: verifyTarget = encoder.encode(protected_header + '.' + base64url_payload)
 * - When b64=false: verifyTarget = encoder.encode(protected_header + '.') + raw_payload
 *
 * This ensures consistency between the verification target and the returned payload,
 * unlike some JOSE implementations that ignore the b64 parameter during verification
 * target construction but consider it during payload extraction.
 *
 * The b64 parameter is defined in {@link https://tools.ietf.org/html/rfc7797 RFC 7797}.
 *
 * @param params - The parameters for encoding the verification target
 * @param params.protectedHeaderB64U - The base64url-encoded protected header
 * @param params.payload - The payload (string when b64=true, Uint8Array when b64=false)
 * @param params.b64 - Whether the payload is base64url-encoded (true) or not (false)
 *
 * @returns An object containing the verification target and decoded payload
 * @throws {Error} When payload type doesn't match b64 parameter
 *
 * @example
 * ```typescript
 * const result = encodeVerifyTarget({
 *   protectedHeaderB64U: "eyJhbGciOiJFUzI1NiJ9",
 *   payload: new Uint8Array([72, 101, 108, 108, 111]), // "Hello"
 *   b64: false
 * });
 * // result.verifyTarget contains encoder.encode("eyJhbGciOiJFUzI1NiJ9.") + payload
 * // result.payload contains the same Uint8Array
 * ```
 *
 * @example
 * ```typescript
 * const result = encodeVerifyTarget({
 *   protectedHeaderB64U: "eyJhbGciOiJFUzI1NiJ9",
 *   payload: "SGVsbG8", // base64url encoded "Hello"
 *   b64: true
 * });
 * // result.verifyTarget contains encoder.encode("eyJhbGciOiJFUzI1NiJ9.SGVsbG8")
 * // result.payload contains decodeBase64Url("SGVsbG8")
 * ```
 */
export const encodeVerifyTarget = ({
  protectedHeaderB64U,
  payload,
  b64,
}: EncodeVerifyTargetParams): EncodeVerifyTargetResult => {
  if (b64) {
    if (typeof payload !== 'string') {
      throw new Error('Payload must be a string when b64=true');
    }

    const payloadB64U = payload;

    return {
      verifyTarget: Uint8Array.from(
        encoder.encode(`${protectedHeaderB64U}.${payloadB64U}`),
      ),
      payload: decodeBase64Url(payloadB64U),
    };
  }

  if (!isUint8Array(payload)) {
    throw new Error('Payload must be a Uint8Array when b64=false');
  }

  const payloadU8A = payload;

  return {
    verifyTarget: concatUint8Arrays(
      encoder.encode(`${protectedHeaderB64U}.`),
      payloadU8A,
    ),
    payload: payloadU8A,
  };
};
