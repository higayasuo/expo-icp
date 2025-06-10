import { Jwk } from '@/jose/types';
import { buildKdfOtherInfo } from '@/jose/jwe/key-management/ecdhes/buildKdfOtherInfo';
import { cekBitLengthByEnc } from '../utils/cekBitLengthByEnc';
import { concatKdf } from '@/jose/jwe/key-management/ecdhes/concatKdf';
import { ManageDecryptKeyParams } from './manageDecryptKey';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { JweInvalid } from '@/jose/errors';
import { parseB64JweHeader } from '../utils/parseB64JweHeader';
import { validateJweEnc } from '../utils/validateJweEnc';

/**
 * Manages the decryption key for ECDH-ES key management.
 * This function:
 * 1. Validates the ephemeral public key and other header parameters
 * 2. Computes the shared secret using ECDH
 * 3. Derives the content encryption key using Concat KDF
 *
 * @param params - The parameters for key management
 * @returns The derived content encryption key
 * @throws {JweInvalid} If any required header parameters are missing or invalid
 */
export const ecdhesManageDecryptKey = ({
  curve,
  myPrivateKey,
  protectedHeader,
}: ManageDecryptKeyParams): Uint8Array => {
  if (!isPlainObject<Jwk>(protectedHeader.epk)) {
    throw new JweInvalid(
      'JOSE Header "epk" (Ephemeral Public Key) missing/invalid',
    );
  }

  const yourPublicKey = curve.toRawPublicKey(protectedHeader.epk);
  const apu = parseB64JweHeader(
    protectedHeader.apu,
    'apu (Agreement PartyUInfo)',
  );
  const apv = parseB64JweHeader(
    protectedHeader.apv,
    'apv (Agreement PartyVInfo)',
  );

  const enc = validateJweEnc(protectedHeader.enc);

  const keyBitLength = cekBitLengthByEnc(enc);
  const sharedSecret = curve
    .getSharedSecret(myPrivateKey, yourPublicKey, true)
    .slice(1);
  const otherInfo = buildKdfOtherInfo({
    algorithm: enc,
    apu,
    apv,
    keyBitLength,
  });

  return concatKdf({ sharedSecret, keyBitLength, otherInfo });
};
