import { concatUint8Arrays, toUint32BE } from 'u8a-utils';

/**
 * Prepends the length of the input array as a 32-bit big-endian value
 * @param {Uint8Array} input - The input byte array
 * @returns {Uint8Array} A new Uint8Array containing the length (as 32-bit BE) followed by the input bytes
 */
export const lengthAndInput = (input: Uint8Array): Uint8Array => {
  return concatUint8Arrays(toUint32BE(input.length), input);
};
