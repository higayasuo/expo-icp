import { JoseInvalid } from '../errors';
import { keyLengthByCrv } from './keyLengthByCrv';

/**
 * Validates the key length for a given curve.
 *
 * This function ensures that:
 * - The key is present.
 * - The key length matches the expected length for the specified curve.
 *
 * @param {Object} params - The parameters for validation.
 * @param {Uint8Array} params.key - The key to validate.
 * @param {string} params.crv - The curve name.
 * @param {string} params.label - The label for the key, used in error messages.
 * @throws {JoseInvalid} If the key is missing or its length is invalid for the specified curve.
 */
type ValidateKeyLengthParams = {
  key: Uint8Array;
  crv: string;
  label: string;
};

/**
 * Validates the key length for a given curve.
 *
 * This function checks that the key is present and that its length matches
 * the expected length for the specified curve.
 *
 * @param {ValidateKeyLengthParams} params - The parameters for validation.
 * @param {Uint8Array} params.key - The key to validate.
 * @param {string} params.crv - The curve name.
 * @param {string} params.label - The label for the key, used in error messages.
 * @throws {JoseInvalid} If the key is missing or its length is invalid for the specified curve.
 */
export const validateKeyLengthByCrv = ({
  key,
  crv,
  label,
}: ValidateKeyLengthParams) => {
  if (key == null) {
    throw new JoseInvalid(`"${label}" is missing`);
  }

  if (key.length !== keyLengthByCrv(crv)) {
    throw new JoseInvalid(`"${label}" is invalid`);
  }
};
