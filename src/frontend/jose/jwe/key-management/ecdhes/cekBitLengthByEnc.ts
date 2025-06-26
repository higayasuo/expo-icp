/**
 * Returns the CEK bit length for a given JWE encryption algorithm
 * @param {string} enc - The JWE encryption algorithm identifier
 * @returns {number} The required CEK bit length for the encryption algorithm
 * @throws {Error} If the encryption algorithm is not supported
 * @example
 * // Returns 256
 * keyBitLengthByEnc('A256GCM');
 * @example
 * // Throws Error: Unsupported JWE Encryption Algorithm: UNKNOWN
 * keyBitLengthByEnc('UNKNOWN');
 */
export function cekBitLengthByEnc(enc: string) {
  switch (enc) {
    case 'A128GCM':
      return 128;
    case 'A192GCM':
      return 192;
    case 'A256GCM':
    case 'A128CBC-HS256':
      return 256;
    case 'A192CBC-HS384':
      return 384;
    case 'A256CBC-HS512':
      return 512;
    default:
      throw new Error(`Unsupported JWE Encryption Algorithm: ${enc}`);
  }
}
