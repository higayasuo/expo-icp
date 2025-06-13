import { JweInvalid } from '@/jose/errors/errors';
import { areDisjoint } from '../../utils/areDisjoint';
import { JweHeaderParameters } from '../../types';
import { isPlainObject } from '@/jose/utils/isPlainObject';

/**
 * Parameters for verifying JWE headers
 * @property {JweHeaderParameters | undefined} protectedHeader - The JWE Protected Header
 * @property {JweHeaderParameters | undefined} sharedUnprotectedHeader - The JWE Shared Unprotected Header
 * @property {JweHeaderParameters | undefined} unprotectedHeader - The JWE Per-Recipient Unprotected Header
 */
type VerifyJweHeadersParams = {
  protectedHeader: JweHeaderParameters | undefined;
  sharedUnprotectedHeader: JweHeaderParameters | undefined;
  unprotectedHeader: JweHeaderParameters | undefined;
};

/**
 * Verifies that the JWE headers are valid according to RFC 7516 §5.2.
 * Ensures that:
 * - At least one header is present
 * - All headers have disjoint keys
 *
 * @param params - The header parameters to verify
 * @throws {JweInvalid} If no headers are present or if headers have duplicate keys
 * @see {@link https://tools.ietf.org/html/rfc7516#section-5.2}
 */
export const verifyJweHeaders = ({
  protectedHeader,
  sharedUnprotectedHeader,
  unprotectedHeader,
}: VerifyJweHeadersParams): void => {
  if (!protectedHeader && !sharedUnprotectedHeader && !unprotectedHeader) {
    throw new JweInvalid(
      'At least one of JWE Protected Header, JWE Shared Unprotected Header, or JWE Per-Recipient Unprotected Header must be present',
    );
  }

  if (
    !areDisjoint(protectedHeader, sharedUnprotectedHeader, unprotectedHeader)
  ) {
    throw new JweInvalid(
      'JWE Protected, JWE Shared Unprotected and JWE Per-Recipient Header Parameter names must be disjoint',
    );
  }

  if (!protectedHeader) {
    throw new JweInvalid('JWE Protected Header is missing');
  }

  if (!isPlainObject(protectedHeader)) {
    throw new JweInvalid('JWE Protected Header is not a plain object');
  }

  if (Object.keys(protectedHeader).length === 0) {
    throw new JweInvalid('JWE Protected Header is empty');
  }

  if (sharedUnprotectedHeader && !isPlainObject(sharedUnprotectedHeader)) {
    throw new JweInvalid('JWE Shared Unprotected Header is not a plain object');
  }

  if (unprotectedHeader && !isPlainObject(unprotectedHeader)) {
    throw new JweInvalid(
      'JWE Per-Recipient Unprotected Header is not a plain object',
    );
  }
};
