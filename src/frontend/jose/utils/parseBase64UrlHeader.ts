import { JoseInvalid } from '@/jose/errors/errors';
import { decodeRequiredBase64Url } from '@/jose/utils/decodeBase64Url';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { getErrorMessage } from '@/jose/utils/getErrorMessage';
import { JoseHeaderParameters } from '@/jose/types';

const decoder = new TextDecoder();

/**
 * Parses a Jose Header from a base64url encoded string.
 *
 * @param headerB64U - The base64url encoded Header to parse
 * @param label - The label for the header
 * @returns The parsed Jose Header Parameters
 * @throws {JoseInvalid} If the input is invalid or cannot be parsed
 */
export const parseBase64UrlHeader = <T extends JoseHeaderParameters>(
  headerB64U: unknown,
  label: string,
): T => {
  const protectedHeader = decodeRequiredBase64Url({
    b64u: headerB64U,
    label,
  });

  try {
    const parsed = JSON.parse(decoder.decode(protectedHeader));

    if (isPlainObject<T>(parsed)) {
      return parsed;
    }

    throw new JoseInvalid(`"${label}" must be a plain object`);
  } catch (error: unknown) {
    console.log(getErrorMessage(error));
    throw new JoseInvalid(`Failed to parse base64url encoded "${label}"`);
  }
};
