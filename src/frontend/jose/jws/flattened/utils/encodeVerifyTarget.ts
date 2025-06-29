import { concatUint8Arrays, decodeBase64Url } from 'u8a-utils';

const encoder = new TextEncoder();
const decoder = new TextDecoder();

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
 * This function creates the verification target string used in JWS signature verification.
 * The verification target is the concatenation of the base64url-encoded protected header,
 * a period (.), and the payload (either base64url-encoded or raw).
 *
 * @param params - The parameters for encoding the verification target
 * @param params.protectedHeaderB64U - The base64url-encoded protected header
 * @param params.payload - The payload as either a Uint8Array or string
 * @param params.b64 - Whether the payload is base64url-encoded (true) or not (false)
 *
 * @returns An object containing the verification target and decoded payload
 *
 * @example
 * ```typescript
 * const result = encodeVerifyTarget({
 *   protectedHeaderB64U: "eyJhbGciOiJFUzI1NiJ9",
 *   payload: "Hello, World!",
 *   b64: false
 * });
 * // result.verifyTarget contains "eyJhbGciOiJFUzI1NiJ9.Hello, World!"
 * // result.payload contains the UTF-8 encoded payload
 * ```
 *
 * @example
 * ```typescript
 * const result = encodeVerifyTarget({
 *   protectedHeaderB64U: "eyJhbGciOiJFUzI1NiJ9",
 *   payload: "SGVsbG8sIFdvcmxkIQ",
 *   b64: true
 * });
 * // result.verifyTarget contains "eyJhbGciOiJFUzI1NiJ9.SGVsbG8sIFdvcmxkIQ"
 * // result.payload contains the decoded base64url payload
 * ```
 */
export const encodeVerifyTarget = ({
  protectedHeaderB64U,
  payload,
  b64,
}: EncodeVerifyTargetParams): EncodeVerifyTargetResult => {
  if (b64) {
    const payloadB64U =
      typeof payload === 'string' ? payload : decoder.decode(payload);

    return {
      verifyTarget: Uint8Array.from(
        encoder.encode(`${protectedHeaderB64U}.${payloadB64U}`),
      ),
      payload: decodeBase64Url(payloadB64U),
    };
  }

  const payloadU8A =
    typeof payload === 'string'
      ? Uint8Array.from(encoder.encode(payload))
      : payload;

  return {
    verifyTarget: concatUint8Arrays(
      encoder.encode(`${protectedHeaderB64U}.`),
      payloadU8A,
    ),
    payload: payloadU8A,
  };
};
