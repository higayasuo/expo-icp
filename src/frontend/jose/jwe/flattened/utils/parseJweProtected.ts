import { JweInvalid } from '@/jose/errors/errors';
import { decodeJweRequiredBase64Url } from '@/jose/utils/decodeBase64Url';
import { JweHeaderParameters } from '../../types';
import { isPlainObject } from '@/jose/utils/isPlainObject';

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
  const protectedHeader = decodeJweRequiredBase64Url({
    b64u: jweProtected,
    label: 'JWE Protected Header',
  });

  try {
    const parsed = JSON.parse(decoder.decode(protectedHeader));

    if (isPlainObject(parsed)) {
      return parsed as JweHeaderParameters;
    }

    throw new JweInvalid('JWE Protected Header is not a plain object');
  } catch (error: unknown) {
    console.error(error);
    throw new JweInvalid(ERROR_MESSAGE);
  }
};
