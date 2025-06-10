import { JweInvalid } from '@/jose/errors';
import { fromB64U } from 'u8a-utils';

/**
 * Parses a base64url-encoded JWE header parameter value.
 *
 * @param b64u - The base64url-encoded value to parse, or undefined
 * @param label - The header parameter name for error messages
 * @returns The decoded Uint8Array, or undefined if input is undefined
 * @throws {JweInvalid} If the input is not a string or fails to decode
 */
export const parseB64JweHeader = (
  b64u: unknown,
  label: string,
): Uint8Array | undefined => {
  if (b64u === undefined) {
    return undefined;
  }

  if (typeof b64u !== 'string') {
    throw new JweInvalid(`JWE Header "${label}" must be a string`);
  }

  try {
    return fromB64U(b64u);
  } catch (e) {
    throw new JweInvalid(`Failed to base64url decode "${label}": ${e}`);
  }
};
