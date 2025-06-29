import { JweEnc } from '@/jose/jwe/types';
import { EcdhCurve } from 'noble-curves-extended';
import { cekBitLengthByEnc } from '@/jose/jwe/key-management/ecdhes/cekBitLengthByEnc';
import { sleep } from '@/jose/utils/sleep';

/**
 * Generates a random Content Encryption Key (CEK) with a random delay
 * to mitigate timing attacks, as recommended in RFC 7516 §11.5.
 *
 * @param curve - The elliptic curve instance used for random byte generation
 * @param enc - The JWE "enc" (Content Encryption Algorithm) identifier
 * @returns A randomly generated CEK of appropriate length for the given "enc"
 * @see https://www.rfc-editor.org/rfc/rfc7516#section-11.5
 */
export const generateMitigatedCek = async (
  curve: EcdhCurve,
  enc: JweEnc,
): Promise<Uint8Array> => {
  // Add a random delay (e.g., between 200ms and 500ms) to further mitigate timing attacks
  await sleep(200 + Math.random() * 300);

  const cekBitLength = cekBitLengthByEnc(enc);
  return curve.randomBytes(cekBitLength >> 3);
};
