/**
 * Extracts the error message from an unknown error object.
 *
 * @param {unknown} error - The error object from which to extract the message.
 * @returns {string} The extracted error message, or a string representation of the error if it's not an instance of Error.
 */
export const getErrorMessage = (error: unknown): string => {
  if (error instanceof Error) {
    return error.message;
  }

  return String(error);
};
