import { JweInvalid, JwsInvalid } from '@/jose/errors';
import { decodeBase64Url as decodeB64U } from 'u8a-utils';

/**
 * Base parameters for decoding base64url-encoded values
 * @typedef {Object} DecodeBase64UrlBaseParams
 * @property {typeof JweInvalid | typeof JwsInvalid} Err - Error constructor to use for validation errors
 * @property {unknown} b64u - The base64url-encoded value to decode, or undefined
 * @property {string} label - The parameter name for error messages
 * @property {boolean} [required=false] - Whether the value is required
 */
export type DecodeBase64UrlBaseParams = {
  Err: typeof JweInvalid | typeof JwsInvalid;
  b64u: unknown;
  label: string;
  required?: boolean;
};

/**
 * General function for decoding base64url-encoded values
 *
 * @param {DecodeBase64UrlBaseParams & { required?: boolean }} params - Parameters for decoding
 * @param {typeof JweInvalid | typeof JwsInvalid} params.Err - Error constructor for validation errors
 * @param {unknown} params.b64u - The base64url-encoded value to decode, or undefined
 * @param {string} params.label - The parameter name for error messages
 * @param {boolean} [params.required=false] - Whether the value is required
 * @returns The decoded Uint8Array, or undefined if input is undefined and not required
 * @throws {JweInvalid | JwsInvalid} If the input is not a string, fails to decode, or is missing when required
 */
const decodeBase64Url = ({
  Err,
  b64u,
  label,
  required = false,
}: DecodeBase64UrlBaseParams): Uint8Array | undefined => {
  if (b64u === undefined) {
    if (required) {
      console.error(`"${label}" is required`);
      throw new Err(`"${label}" is invalid`);
    }
    return undefined;
  }

  if (typeof b64u !== 'string') {
    console.error(`"${label}" must be a string`);
    throw new Err(`"${label}" is invalid`);
  }

  try {
    return decodeB64U(b64u);
  } catch (e) {
    console.error(`Failed to base64url decode "${label}": ${e}`);
    throw new Err(`"${label}" is invalid`);
  }
};

/**
 * Decodes an optional base64url-encoded value.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'required'>} params - Parameters for decoding
 * @param {typeof JweInvalid | typeof JwsInvalid} params.Err - Error constructor for validation errors
 * @param {unknown} params.b64u - The base64url-encoded value to decode, or undefined
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array, or undefined if input is undefined
 * @throws {JweInvalid | JwsInvalid} If the input is not a string or fails to decode
 */
const decodeOptionalBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'required'>,
): Uint8Array | undefined => {
  return decodeBase64Url({ ...params, required: false });
};

/**
 * Decodes a required base64url-encoded value.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'required'>} params - Parameters for decoding
 * @param {typeof JweInvalid | typeof JwsInvalid} params.Err - Error constructor for validation errors
 * @param {unknown} params.b64u - The base64url-encoded value to decode
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array
 * @throws {JweInvalid | JwsInvalid} If the input is not a string, fails to decode, or is missing
 */
const decodeRequiredBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'required'>,
): Uint8Array => {
  const result = decodeBase64Url({ ...params, required: true });
  // Since required is true, result is guaranteed to be Uint8Array
  return result!;
};

/**
 * Decodes an optional base64url-encoded value for JWE.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode, or undefined
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array, or undefined if input is undefined
 * @throws {JweInvalid} If the input is not a string or fails to decode
 */
export const decodeJweOptionalBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>,
): Uint8Array | undefined => {
  return decodeOptionalBase64Url({ ...params, Err: JweInvalid });
};

/**
 * Decodes a required base64url-encoded value for JWE.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array
 * @throws {JweInvalid} If the input is not a string, fails to decode, or is missing
 */
export const decodeJweRequiredBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>,
): Uint8Array => {
  return decodeRequiredBase64Url({ ...params, Err: JweInvalid });
};

/**
 * Decodes an optional base64url-encoded value for JWS.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode, or undefined
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array, or undefined if input is undefined
 * @throws {JwsInvalid} If the input is not a string or fails to decode
 */
export const decodeJwsOptionalBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>,
): Uint8Array | undefined => {
  return decodeOptionalBase64Url({ ...params, Err: JwsInvalid });
};

/**
 * Decodes a required base64url-encoded value for JWS.
 *
 * @param {Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>} params - Parameters for decoding
 * @param {unknown} params.b64u - The base64url-encoded value to decode
 * @param {string} params.label - The parameter name for error messages
 * @returns The decoded Uint8Array
 * @throws {JwsInvalid} If the input is not a string, fails to decode, or is missing
 */
export const decodeJwsRequiredBase64Url = (
  params: Omit<DecodeBase64UrlBaseParams, 'Err' | 'required'>,
): Uint8Array => {
  return decodeRequiredBase64Url({ ...params, Err: JwsInvalid });
};
