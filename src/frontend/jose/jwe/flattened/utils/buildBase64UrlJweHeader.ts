import { encodeBase64Url } from 'u8a-utils';

const encoder = new TextEncoder();

/**
 * Builds a base64url-encoded JWE header from a given header object.
 * Can be used for protected, shared unprotected, or per-recipient unprotected headers.
 */
export const buildBase64UrlJweHeader = (header: object | undefined): string => {
  if (!header) {
    return '';
  }

  return encodeBase64Url(encoder.encode(JSON.stringify(header)));
};
