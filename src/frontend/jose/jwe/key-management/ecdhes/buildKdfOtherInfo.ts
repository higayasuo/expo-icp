import { concatUint8Arrays, toUint32BE } from 'u8a-utils';
import { lengthAndInput } from './lengthAndInput';
import { JweInvalid, JweNotSupported } from '@/jose/errors';
import { isEnc } from 'aes-universal';

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
  apu?: Uint8Array;
  apv?: Uint8Array;
  keyBitLength: number;
};

/**
 * Builds the KDF Other Info structure according to RFC 7518
 * @param {BuildKdfOtherInfoParams} params - Parameters for building KDF Other Info
 * @returns {Uint8Array} - Concatenated Other Info structure
 */
export const buildKdfOtherInfo = ({
  algorithm,
  apu = new Uint8Array(),
  apv = new Uint8Array(),
  keyBitLength,
}: BuildKdfOtherInfoParams) => {
  // RFC 7518 §4.6.1.2
  if (apu?.byteLength > 32 || apv?.byteLength > 32) {
    throw new JweInvalid('APU/APV must be ≤32 bytes');
  }

  if (!isEnc(algorithm)) {
    console.error(
      `"enc" (Content Encryption Algorithm) is not supported: ${algorithm}`,
    );
    throw new JweNotSupported(
      '"enc" (Content Encryption Algorithm) is not supported',
    );
  }

  return concatUint8Arrays(
    lengthAndInput(encoder.encode(algorithm)), // AlgorithmID (4.6.2.1)
    lengthAndInput(apu), // PartyUInfo (4.6.2.2)
    lengthAndInput(apv), // PartyVInfo (4.6.2.3)
    toUint32BE(keyBitLength), // SuppPubInfo (4.6.2.4)
  );
};
