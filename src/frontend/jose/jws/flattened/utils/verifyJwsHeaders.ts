import { JwsInvalid } from '@/jose/errors/errors';
import { areDisjoint } from '@/jose/utils/areDisjoint';
import { JwsHeaderParameters } from '@/jose/jws/types';
import { isPlainObject } from '@/jose/utils/isPlainObject';

/**
 * Parameters for verifying JWS headers
 * @property {JwsHeaderParameters | undefined} protectedHeader - The JWS Protected Header
 * @property {JwsHeaderParameters | undefined} unprotectedHeader - The JWS Unprotected Header
 */
type VerifyJwsHeadersParams = {
  protectedHeader: JwsHeaderParameters | undefined;
  unprotectedHeader: JwsHeaderParameters | undefined;
};

/**
 * Verifies that the JWS headers are valid.
 * Ensures that:
 * - The protected header is present and is a non-empty plain object
 * - The unprotected header, if present, is a plain object
 * - The headers have disjoint keys
 *
 * @param {VerifyJwsHeadersParams} params - The header parameters to verify
 * @throws {JwsInvalid} If the protected header is missing, not a plain object, or empty
 * @throws {JwsInvalid} If the unprotected header is not a plain object
 * @throws {JwsInvalid} If the headers have duplicate keys
 */
export const verifyJwsHeaders = ({
  protectedHeader,
  unprotectedHeader,
}: VerifyJwsHeadersParams): void => {
  if (!protectedHeader) {
    throw new JwsInvalid('JWS Protected Header is missing');
  }

  if (!isPlainObject(protectedHeader)) {
    throw new JwsInvalid('JWS Protected Header is not a plain object');
  }

  if (Object.keys(protectedHeader).length === 0) {
    throw new JwsInvalid('JWS Protected Header is empty');
  }

  if (unprotectedHeader && !isPlainObject(unprotectedHeader)) {
    throw new JwsInvalid('JWS Unprotected Header is not a plain object');
  }

  if (!areDisjoint(protectedHeader, unprotectedHeader)) {
    throw new JwsInvalid(
      'JWS Protected and JWS Unprotected Header Parameter names must be disjoint',
    );
  }
};
