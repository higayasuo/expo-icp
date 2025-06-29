import {
  AbstractJoseError,
  JoseInvalid,
  JweInvalid,
  JwsInvalid,
} from '@/jose/errors';
import { decodeBase64Url as decodeB64U } from 'u8a-utils';

/**
 * Base parameters for decoding base64url-encoded values
 * @typedef {Object} DecodeBase64UrlBaseParams
 * @property {unknown} b64u - The base64url-encoded value to decode, or undefined
 * @property {string} label - The parameter name for error messages
 * @property {boolean} [required=false] - Whether the value is required
 */
export type DecodeBase64UrlBaseParams = {
  b64u: unknown;
  label: string;
  required?: boolean;
};

/**
 * General function for decoding base64url-encoded values
 *
 * @param {DecodeBase64UrlBaseParams & { required?: boolean }} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode, or undefined
 * @param {string} params.label - The parameter name for error messages
 * @param {boolean} [params.required=false] - Whether the value is required
 * @returns The decoded Uint8Array, or undefined if input is undefined and not required
 * @throws {JoseInvalid} If the input is not a string, fails to decode, or is missing when required
 */
const decodeBase64Url = ({
  b64u,
  label,
  required = false,
}: DecodeBase64UrlBaseParams): Uint8Array | undefined => {
  if (b64u == null) {
    if (required) {
      throw new JoseInvalid(`"${label}" is missing`);
    }
    return undefined;
  }

  if (typeof b64u !== 'string') {
    throw new JoseInvalid(`"${label}" must be a string`);
  }

  try {
    return decodeB64U(b64u);
  } catch (e) {
    throw new JoseInvalid(`Failed to base64url decode "${label}"`);
  }
};

/**
 * Decodes an optional base64url-encoded value.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'required'>} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode, or undefined
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array, or undefined if input is undefined
 * @throws {JoseInvalid} If the input is not a string or fails to decode
 */
export const decodeOptionalBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'required'>,
): Uint8Array | undefined => {
  return decodeBase64Url({ ...params, required: false });
};

/**
 * Decodes a required base64url-encoded value.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'required'>} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array
 * @throws {JoseInvalid} If the input is not a string, fails to decode, or is missing
 */
export const decodeRequiredBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'required'>,
): Uint8Array => {
  const result = decodeBase64Url({ ...params, required: true });
  // Since required is true, result is guaranteed to be Uint8Array
  return result!;
};
