import { encodeBase64Url } from 'u8a-utils';

const encoder = new TextEncoder();

/**
 * Encodes a header object to base64url format.
 * Can be used for protected, shared unprotected, or per-recipient unprotected headers.
 */
export const encodeBase64UrlHeader = (header: object | undefined): string => {
  if (!header) {
    return '';
  }

  return encodeBase64Url(encoder.encode(JSON.stringify(header)));
};
