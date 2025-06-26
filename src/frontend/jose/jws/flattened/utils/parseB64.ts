import { JwsInvalid } from '@/jose/errors';

/**
 * Parses the "b64" (base64url-encode payload) Header Parameter.
 *
 * @param {unknown} b64 - The value of the "b64" parameter to parse.
 * @param {Set<string>} criticalParamNames - A set of critical parameter names.
 * @returns {boolean} - Returns the parsed boolean value of the "b64" parameter.
 * @throws {JwsInvalid} - Throws if the "b64" parameter is not a boolean when it is critical.
 */
export const parseB64 = (
  b64: unknown,
  criticalParamNames: Set<string>,
): boolean => {
  if (criticalParamNames.has('b64')) {
    b64 = b64 ?? true;
    if (typeof b64 !== 'boolean') {
      throw new JwsInvalid(
        'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
      );
    }

    return b64;
  }

  return true;
};
