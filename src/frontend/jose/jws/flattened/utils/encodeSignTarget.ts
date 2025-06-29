import { encodeBase64UrlHeader } from '@/jose/utils/encodeBase64UrlHeader';
import { concatUint8Arrays, encodeBase64Url } from 'u8a-utils';

const encoder = new TextEncoder();

type EncodeSignTargetParams = {
  protectedHeader: object | undefined;
  payload: Uint8Array;
  b64: boolean;
};

type EncodeSignTargetResult = {
  signTarget: Uint8Array;
  protectedHeaderB64U: string;
  payloadB64U: string;
};

/**
 * Encodes the signing target for JWS according to RFC 7797.
 *
 * When b64 is true:
 * - Payload is Base64URL encoded
 * - Signing target is "base64url(header).base64url(payload)"
 *
 * When b64 is false:
 * - Payload is used as-is (binary)
 * - Signing target is "base64url(header).payload"
 *
 * @param {EncodeSignTargetParams} params - Parameters for encoding
 * @param {object | undefined} params.protectedHeader - JWS protected header
 * @param {Uint8Array} params.payload - Payload to sign
 * @param {boolean} params.b64 - Whether to Base64URL encode the payload
 * @returns {EncodeSignTargetResult} The encoded signing target and payload Base64URL
 */
export const encodeSignTarget = ({
  protectedHeader,
  payload,
  b64,
}: EncodeSignTargetParams): EncodeSignTargetResult => {
  const protectedHeaderB64U = encodeBase64UrlHeader(protectedHeader);

  if (b64) {
    const payloadB64U = encodeBase64Url(payload);

    return {
      signTarget: Uint8Array.from(
        encoder.encode(`${protectedHeaderB64U}.${payloadB64U}`),
      ),
      protectedHeaderB64U,
      payloadB64U,
    };
  }

  return {
    signTarget: concatUint8Arrays(
      encoder.encode(`${protectedHeaderB64U}.`),
      payload,
    ),
    protectedHeaderB64U,
    payloadB64U: '',
  };
};
