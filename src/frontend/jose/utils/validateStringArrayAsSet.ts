/**
 * Validates and converts an array of strings into a Set of strings.
 *
 * This function ensures that:
 * - If the input is undefined, returns undefined
 * - The input is an array
 * - All elements in the array are strings
 *
 * @param {unknown} value - The value to validate and convert
 * @param {string} name - The name of the parameter being validated (used in error messages)
 * @returns {Set<string> | undefined} - Returns a Set of strings if valid, undefined if input is undefined
 * @throws {TypeError} - If the input is not an array or contains non-string elements
 */
export const validateStringArrayAsSet = (
  value: unknown,
  name: string,
): Set<string> | undefined => {
  if (value === undefined) {
    return undefined;
  }

  if (!Array.isArray(value)) {
    throw new TypeError(`${name} must be an array`);
  }

  if (value.some((v) => typeof v !== 'string')) {
    throw new TypeError(`${name} must be an array of strings`);
  }

  return new Set(value);
};
