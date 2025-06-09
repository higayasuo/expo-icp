/**
 * Checks if there are no duplicate keys across multiple header objects.
 *
 * This function takes a variable number of header objects and verifies that
 * there are no duplicate keys across all of them. It returns true if all keys
 * are unique across the headers, and false if any key appears in more than one header.
 *
 * @param {...Array<object | undefined>} headers - Variable number of header objects to check
 * @returns {boolean} True if there are no duplicate keys across all headers, false otherwise
 */
export const hasNoDuplicateKeys = (...headers: Array<object | undefined>) => {
  const sources = headers.filter(Boolean) as object[];

  if (sources.length === 0 || sources.length === 1) {
    return true;
  }

  const acc = new Set<string>(Object.keys(sources[0]));

  for (let i = 1; i < sources.length; i++) {
    const parameters = Object.keys(sources[i]);
    const hasDuplicate = parameters.some((parameter) => acc.has(parameter));
    if (hasDuplicate) {
      return false;
    }
    parameters.forEach(acc.add, acc);
  }

  return true;
};
