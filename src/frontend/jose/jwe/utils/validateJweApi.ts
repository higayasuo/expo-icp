import { JweInvalid } from '@/jose/errors/errors';
import { ensureUint8Array, isUint8Array } from 'u8a-utils';

type PartyInfoType = 'Agreement PartyUInfo' | 'Agreement PartyVInfo';

/**
 * Validates a JWE party info parameter (apu or apv).
 *
 * This function ensures that:
 * - The parameter is either undefined or a Uint8Array.
 * - If defined, the parameter must not exceed 32 bytes in length.
 *
 * @param {unknown} value - The parameter value to validate.
 * @param {PartyInfoType} type - The type of party info ('Agreement PartyUInfo' or 'Agreement PartyVInfo').
 * @returns {Uint8Array | undefined} The validated value as a Uint8Array, or undefined if not provided.
 * @throws {JweInvalid} If the parameter is not a Uint8Array or exceeds 32 bytes in length.
 */
const validatePartyInfo = (
  value: unknown,
  type: PartyInfoType,
): Uint8Array | undefined => {
  if (!value) {
    return undefined;
  }

  if (!isUint8Array(value)) {
    console.error(`${type} must be a Uint8Array`);
    throw new JweInvalid(`${type} must be a Uint8Array`);
  }

  const valueU8a = ensureUint8Array(value);

  if (valueU8a.byteLength > 32) {
    console.error(
      `${type} must be less than or equal to 32 bytes: value.byteLength (${value.byteLength})`,
    );
    throw new JweInvalid(`${type} must be less than or equal to 32 bytes`);
  }

  return valueU8a;
};

/**
 * Validates the JWE "apu" (Agreement PartyUInfo) parameter.
 *
 * @param {unknown} apu - The "apu" parameter value to validate.
 * @returns {Uint8Array | undefined} The validated "apu" as a Uint8Array, or undefined if not provided.
 * @throws {JweInvalid} If the "apu" parameter is not a Uint8Array or exceeds 32 bytes in length.
 */
export const validateJweApu = (apu: unknown): Uint8Array | undefined => {
  return validatePartyInfo(apu, 'Agreement PartyUInfo');
};

/**
 * Validates the JWE "apv" (Agreement PartyVInfo) parameter.
 *
 * @param {unknown} apv - The "apv" parameter value to validate.
 * @returns {Uint8Array | undefined} The validated "apv" as a Uint8Array, or undefined if not provided.
 * @throws {JweInvalid} If the "apv" parameter is not a Uint8Array or exceeds 32 bytes in length.
 */
export const validateJweApv = (apv: unknown): Uint8Array | undefined => {
  return validatePartyInfo(apv, 'Agreement PartyVInfo');
};
