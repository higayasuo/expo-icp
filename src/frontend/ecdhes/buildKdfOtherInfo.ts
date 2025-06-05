import { concatUint8Arrays, toUint32BE } from 'u8a-utils';
import { lengthAndInput } from './lengthAndInput';

const encoder = new TextEncoder();

/**
 * Parameters for building KDF Other Info
 * @typedef {Object} BuildKdfOtherInfoParams
 * @property {string} algorithm - The algorithm identifier
 * @property {Uint8Array} apu - PartyUInfo (typically a public key or identifier)
 * @property {Uint8Array} apv - PartyVInfo (typically a public key or identifier)
 * @property {number} keyBitLength - The desired key length in bits
 */

export type BuildKdfOtherInfoParams = {
  algorithm: string;
  apu: Uint8Array;
  apv: Uint8Array;
  keyBitLength: number;
};

/**
 * Builds the KDF Other Info structure according to RFC 7518
 * @param {BuildKdfOtherInfoParams} params - Parameters for building KDF Other Info
 * @returns {Uint8Array} - Concatenated Other Info structure
 */
export const buildKdfOtherInfo = ({
  algorithm,
  apu,
  apv,
  keyBitLength,
}: BuildKdfOtherInfoParams) => {
  return concatUint8Arrays(
    lengthAndInput(encoder.encode(algorithm)),
    lengthAndInput(apu),
    lengthAndInput(apv),
    toUint32BE(keyBitLength),
  );
};
