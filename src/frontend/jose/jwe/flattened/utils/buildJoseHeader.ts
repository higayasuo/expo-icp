import { JweHeaderParameters } from '../../types';
import { JweNotSupported } from '@/jose/errors/errors';
import { verifyJweHeaders } from './verifyJweHeaders';

/**
 * Parameters for building a JOSE header
 * @property {JweHeaderParameters | undefined} protectedHeader - The JWE Protected Header
 * @property {JweHeaderParameters | undefined} sharedUnprotectedHeader - The JWE Shared Unprotected Header
 * @property {JweHeaderParameters | undefined} unprotectedHeader - The JWE Per-Recipient Unprotected Header
 */
type BuildJoseHeaderParams = {
  protectedHeader: JweHeaderParameters | undefined;
  sharedUnprotectedHeader: JweHeaderParameters | undefined;
  unprotectedHeader: JweHeaderParameters | undefined;
};

/**
 * Builds JOSE Header according to RFC 7516 §5.2.
 * The headers are merged in the following order:
 * 1. JWE Per-Recipient Unprotected Header
 * 2. JWE Shared Unprotected Header
 * 3. JWE Protected Header
 *
 * @param params - The header parameters to merge
 * @returns The merged JWE header
 * @throws {JweInvalid} If no headers are present or if headers have duplicate keys
 * @throws {JweNotSupported} If the "zip" header parameter is present
 * @see {@link https://tools.ietf.org/html/rfc7516#section-5.2}
 */
export const buildJoseHeader = ({
  protectedHeader,
  sharedUnprotectedHeader,
  unprotectedHeader,
}: BuildJoseHeaderParams): JweHeaderParameters => {
  verifyJweHeaders({
    protectedHeader,
    sharedUnprotectedHeader,
    unprotectedHeader,
  });

  const joseHeader: JweHeaderParameters = {
    ...unprotectedHeader,
    ...sharedUnprotectedHeader,
    ...protectedHeader,
  };

  if (joseHeader.zip !== undefined) {
    throw new JweNotSupported(
      'JWE "zip" (Compression Algorithm) Header Parameter is not supported.',
    );
  }

  return joseHeader;
};
