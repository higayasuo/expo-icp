import { JweInvalid } from '@/jose/errors/errors';
import { decodeRequiredBase64Url } from '@/jose/utils/decodeBase64Url';
import { JweHeaderParameters } from '../../types';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { getErrorMessage } from '@/jose/utils/getErrorMessage';

const ERROR_MESSAGE = 'JWE Protected Header is invalid';

const decoder = new TextDecoder();

/**
 * Parses a JWE Protected Header from a base64url encoded string.
 *
 * @param jweProtected - The base64url encoded JWE Protected Header to parse
 * @returns The parsed JWE Header Parameters
 * @throws {JweInvalid} If the input is invalid or cannot be parsed
 */
export const parseJweProtected = (
  jweProtected: unknown,
): JweHeaderParameters => {
  const protectedHeader = decodeRequiredBase64Url({
    b64u: jweProtected,
    label: 'JWE Protected Header',
  });

  try {
    const parsed = JSON.parse(decoder.decode(protectedHeader));

    if (isPlainObject<JweHeaderParameters>(parsed)) {
      return parsed;
    }

    throw new JweInvalid('JWE Protected Header must be a plain object');
  } catch (error: unknown) {
    console.log(getErrorMessage(error));
    throw new JweInvalid(ERROR_MESSAGE);
  }
};
