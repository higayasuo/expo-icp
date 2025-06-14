import { buildKdfOtherInfo } from '@/jose/jwe/key-management/ecdhes/buildKdfOtherInfo';
import { cekBitLengthByEnc } from '../utils/cekBitLengthByEnc';
import { concatKdf } from '@/jose/jwe/key-management/ecdhes/concatKdf';
import { DeriveDecryptionKeyParams } from './deriveDecryptionKey';
import { decodeJweOptionalBase64Url } from '../../utils/decodeBase64Url';
import { validateJweEpk } from '../utils/validateJweEpk';
import { JweInvalid } from '@/jose/errors/errors';
import { validateJweApu, validateJweApv } from '../utils/validateJweApi';
import { validateJweEnc } from '../utils/validateJweEnc';
import { validateJwkPublicKeyAgainstCurve } from '@/jose/utils/validateJwkPublicKeyAgainstCurve';

/**
 * Derives a decryption key using ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) method.
 *
 * @param {DeriveDecryptionKeyParams} params - The parameters required for deriving the decryption key.
 * @param {JweEnc} params.enc - The encryption algorithm to be used.
 * @param {NistCurve} params.curve - The elliptic curve to be used for key derivation.
 * @param {Uint8Array} params.myPrivateKey - The private key of the recipient.
 * @param {JweHeaderParameters} params.protectedHeader - The protected header containing necessary parameters.
 * @returns {Uint8Array} The derived decryption key.
 */
export const ecdhesDeriveDecryptionKey = ({
  enc,
  curve,
  myPrivateKey,
  protectedHeader,
}: DeriveDecryptionKeyParams): Uint8Array => {
  const epk = validateJweEpk(protectedHeader.epk);
  const yourPublicKey = validateJwkPublicKeyAgainstCurve(epk, curve);

  if (!curve.utils.isValidPrivateKey(myPrivateKey)) {
    throw new JweInvalid('Invalid private key');
  }

  const apu = decodeJweOptionalBase64Url({
    b64u: protectedHeader.apu,
    label: 'apu (Agreement PartyUInfo)',
  });
  const apv = decodeJweOptionalBase64Url({
    b64u: protectedHeader.apv,
    label: 'apv (Agreement PartyVInfo)',
  });

  if (apu) {
    validateJweApu(apu);
  }

  if (apv) {
    validateJweApv(apv);
  }

  const validatedEnc = validateJweEnc(enc);

  const keyBitLength = cekBitLengthByEnc(validatedEnc);
  // getSharedSecret returns a compressed SEC format (0x02 or 0x03 prefix)
  // We need to remove the prefix to get the raw shared secret
  const sharedSecret = curve
    .getSharedSecret(myPrivateKey, yourPublicKey, true)
    .slice(1);
  const otherInfo = buildKdfOtherInfo({
    algorithm: validatedEnc,
    apu,
    apv,
    keyBitLength,
  });

  return concatKdf({ sharedSecret, keyBitLength, otherInfo });
};
