import { toUint32BE } from 'u8a-utils';
import { sha256 } from '@noble/hashes/sha2';

/**
 * Parameters for the Concatenation Key Derivation Function (Concat KDF)
 * @typedef {Object} ConcatKdfParams
 * @property {Uint8Array} sharedSecret - The shared secret used as input to the KDF
 * @property {number} keyBitLength - The desired output length in bits
 * @property {Uint8Array} otherInfo - Additional context/application-specific information
 */
export type ConcatKdfParams = {
  /** The shared secret used as input to the KDF */
  sharedSecret: Uint8Array;
  /** The desired output length in bits */
  keyBitLength: 128 | 192 | 256 | 384 | 512;
  /** Additional context/application-specific information */
  otherInfo: Uint8Array;
};

/**
 * Implements the Concatenation Key Derivation Function (Concat KDF) as specified in NIST SP 800-56A
 * using SHA-256 as the hash function.
 *
 * The implementation follows RFC 7518 §4.6.2 Concat KDF Pseudocode:
 * 1. Initialize a 32-bit, big-endian counter set to 1.
 * 2. For i = 1 to ceil(keydatalen / hashlen):
 *    a. Compute Hashi = SHA-256(counter || Z || OtherInfo)
 *    b. Increment counter (modulo 2^32)
 * 3. Set K = leftmost(Hash1 || Hash2 || ... || Hashi, keydatalen)
 *
 * Where:
 * - Z = sharedSecret
 * - OtherInfo = otherInfo
 * - hashlen = 32 (SHA-256 output size in bytes)
 * - keydatalen = keyBitLength >> 3 (convert bits to bytes)
 * - "||" denotes concatenation
 *
 * @param {ConcatKdfParams} params - The parameters for the KDF
 * @param {Uint8Array} params.sharedSecret - The shared secret used as input to the KDF
 * @param {number} params.keyBitLength - The desired output length in bits
 * @param {Uint8Array} params.otherInfo - Additional context/application-specific information
 * @returns {Uint8Array} The derived key material with length equal to keyBitLength / 8 bytes
 * @throws {RangeError} If keyBitLength is not a positive integer
 * @see {@link https://datatracker.ietf.org/doc/html/rfc7518#section-4.6.2}
 *
 * @example
 * const sharedSecret = new Uint8Array([...]);
 * const keyMaterial = concatKdf({
 *   sharedSecret,
 *   keyBitLength: 256,
 *   otherInfo: new Uint8Array([...])
 * });
 */
export const concatKdf = ({
  sharedSecret,
  keyBitLength,
  otherInfo,
}: ConcatKdfParams): Uint8Array => {
  if (!Number.isInteger(keyBitLength) || keyBitLength <= 0) {
    throw new RangeError('keyBitLength must be a positive integer');
  }
  const iterations = Math.ceil((keyBitLength >> 3) / 32);
  const res = new Uint8Array(iterations * 32);

  for (let iter = 0; iter < iterations; iter++) {
    const buf = new Uint8Array(4 + sharedSecret.length + otherInfo.length);
    buf.set(toUint32BE(iter + 1));
    buf.set(sharedSecret, 4);
    buf.set(otherInfo, 4 + sharedSecret.length);
    res.set(sha256(buf), iter * 32);
  }
  return res.slice(0, keyBitLength >> 3);
};
