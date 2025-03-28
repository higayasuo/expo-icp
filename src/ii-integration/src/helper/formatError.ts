/**
 * Formats an error message with a given prefix.
 *
 * @param {string} prefix - The prefix to add to the error message.
 * @param {unknown} error - The error to format.
 * @returns {string} The formatted error message.
 */
export const formatError = (prefix: string, error: unknown): string => {
  return `Internet Identity ${prefix}: ${
    error instanceof Error ? error.message : String(error)
  }`;
};
