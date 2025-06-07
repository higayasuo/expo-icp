import { JoseNotSupported, JweInvalid, JwsInvalid } from '../errors';

/**
 * Represents a JOSE header that may contain critical parameters
 * @typedef {Object} ValidateCritHeader
 * @property {string[]} [crit] - Array of critical header parameter names
 * @property {unknown} [propName] - Additional header parameters
 */
export type ValidateCritHeader = {
  crit?: string[];
  [propName: string]: unknown | undefined;
};

/**
 * Parameters for validating critical header parameters
 * @typedef {Object} ValidateCritParams
 * @property {typeof JweInvalid | typeof JwsInvalid} Err - Error constructor to use for validation errors
 * @property {string[]} [recognizedDefault] - Array of default recognized parameters
 * @property {string[]} [recognizedOption] - Array of optional recognized parameters
 * @property {ValidateCritHeader} [protectedHeader] - Protected header containing critical parameters
 * @property {ValidateCritHeader} joseHeader - Complete JOSE header
 */
export type ValidateCritParams = {
  Err: typeof JweInvalid | typeof JwsInvalid;
  recognizedDefault?: string[];
  recognizedOption: string[] | undefined;
  protectedHeader: ValidateCritHeader | undefined;
  joseHeader: ValidateCritHeader;
};

/**
 * Validates critical header parameters according to JOSE specifications
 * @param {ValidateCritParams} params - Parameters for validation
 * @param {typeof JweInvalid | typeof JwsInvalid} params.Err - Error constructor to use for validation errors
 * @param {string[]} [params.recognizedDefault] - Array of default recognized parameters
 * @param {string[]} [params.recognizedOption] - Array of optional recognized parameters
 * @param {ValidateCritHeader} [params.protectedHeader] - Protected header containing critical parameters
 * @param {ValidateCritHeader} params.joseHeader - Complete JOSE header
 * @returns {Set<string>} Set of validated critical parameter names
 * @throws {JoseNotSupported} If an unrecognized critical parameter is found
 * @throws {JweInvalid | JwsInvalid} If critical parameters are invalid or missing
 */
export const validateCrit = ({
  Err,
  recognizedDefault = [],
  recognizedOption = [],
  protectedHeader,
  joseHeader,
}: ValidateCritParams): Set<string> => {
  if (joseHeader.crit !== undefined && protectedHeader?.crit === undefined) {
    throw new Err(
      '"crit" (Critical) Header Parameter MUST be integrity protected',
    );
  }

  if (!protectedHeader || protectedHeader.crit === undefined) {
    return new Set();
  }

  if (
    !Array.isArray(protectedHeader.crit) ||
    protectedHeader.crit.length === 0 ||
    protectedHeader.crit.some(
      (input) => typeof input !== 'string' || input.length === 0,
    )
  ) {
    throw new Err(
      '"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present',
    );
  }

  const recognized = new Set([...recognizedDefault, ...recognizedOption]);

  for (const parameter of protectedHeader.crit) {
    if (!recognized.has(parameter)) {
      throw new JoseNotSupported(
        `Extension Header Parameter "${parameter}" is not recognized`,
      );
    }

    if (joseHeader[parameter] === undefined) {
      throw new Err(`Extension Header Parameter "${parameter}" is missing`);
    }

    if (protectedHeader[parameter] === undefined) {
      throw new Err(
        `Extension Header Parameter "${parameter}" MUST be integrity protected`,
      );
    }
  }

  return new Set(protectedHeader.crit);
};
