/**
 * Checks if a value is object-like (not null and has typeof 'object' with [object Object] tag).
 *
 * @param value - The value to check
 * @returns True if the value is object-like, false otherwise
 */
export const isObjectLike = (value: unknown) => {
  return (
    typeof value === 'object' &&
    value !== null &&
    Object.prototype.toString.call(value) === '[object Object]'
  );
};

/**
 * Checks if a value is a plain object (object created by Object constructor or with null prototype).
 *
 * @typeParam T - The expected type of the plain object (defaults to object)
 * @param input - The value to check
 * @returns True if the value is a plain object, false otherwise
 */
export const isPlainObject = <T = object>(input: unknown): input is T => {
  if (!isObjectLike(input)) {
    return false;
  }

  const proto = Object.getPrototypeOf(input);

  return proto === null || proto === Object.prototype;
};
