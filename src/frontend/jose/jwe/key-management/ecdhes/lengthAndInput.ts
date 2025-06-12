import { concatUint8Arrays, toUint32BE } from 'u8a-utils';

/**
 * Prepends a 32-bit big-endian length to the input, as required by RFC 7518 §4.6.2 (Concat KDF OtherInfo).
 * @param input - The input Uint8Array
 * @returns A new Uint8Array: [length (4 bytes BE)] + input
 */
export const lengthAndInput = (input: Uint8Array): Uint8Array => {
  if (input.length > 0xffffffff) {
    throw new RangeError('Input too large');
  }
  return concatUint8Arrays(toUint32BE(input.length), input);
};
