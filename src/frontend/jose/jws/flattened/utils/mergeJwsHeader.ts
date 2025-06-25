import { JwsHeaderParameters } from '@/jose/jws/types';
import { verifyJwsHeaders } from './verifyJwsHeaders';

type MergeJwsHeadersParams = {
  protectedHeader: JwsHeaderParameters | undefined;
  unprotectedHeader: JwsHeaderParameters | undefined;
};

/**
 * Merges JWS Protected and Unprotected Headers according to RFC 7515.
 * The headers are merged in the following order:
 * 1. JWS Unprotected Header
 * 2. JWS Protected Header (takes precedence)
 *
 * @param params - The header parameters to merge
 * @returns The merged JWS header
 * @throws {JwsInvalid} If the headers are invalid or have duplicate keys
 * @see {@link https://tools.ietf.org/html/rfc7515#section-5.2}
 */
export const mergeJwsHeaders = ({
  protectedHeader,
  unprotectedHeader,
}: MergeJwsHeadersParams): JwsHeaderParameters => {
  verifyJwsHeaders({
    protectedHeader,
    unprotectedHeader,
  });

  return {
    ...unprotectedHeader,
    ...protectedHeader,
  };
};
