/**
 * Checks if multiple JWE headers have disjoint parameter names.
 *
 * This function is used to ensure that JWE Protected, JWE Shared Unprotected,
 * and JWE Per-Recipient Unprotected Header Parameter names are disjoint as
 * required by the JWE specification (RFC 7516).
 *
 * @param {...Array<object | undefined>} headers - An array of header objects to check
 * @returns {boolean} True if all headers have disjoint parameter names, false if any parameter names overlap
 * @example
 * // Returns true
 * areDisjoint({ alg: 'ECDH-ES' }, { enc: 'A256GCM' });
 * @example
 * // Returns false
 * areDisjoint({ alg: 'ECDH-ES' }, { alg: 'A256GCM' });
 */
export const areDisjoint = (...headers: Array<object | undefined>) => {
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
