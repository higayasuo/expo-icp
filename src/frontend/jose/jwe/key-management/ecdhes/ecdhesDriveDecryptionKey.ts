import { buildKdfOtherInfo } from '@/jose/jwe/key-management/ecdhes/buildKdfOtherInfo';
import { cekBitLengthByEnc } from './cekBitLengthByEnc';
import { concatKdf } from '@/jose/jwe/key-management/ecdhes/concatKdf';
import { DeriveDecryptionKeyParams } from '../deriveDecryptionKey';
import { decodeOptionalBase64Url } from '@/jose/utils/decodeBase64Url';
import { validateJweEpk } from '@/jose/jwe/utils/validateJweEpk';
import {
  validateJweApu,
  validateJweApv,
} from '@/jose/jwe/utils/validateJweApi';
import { validateJweEnc } from '../../utils/validateJweEnc';
import { JweAlg, JweEnc, JweHeaderParameters } from '@/jose/jwe/types';
import { EcdhCurve } from 'noble-curves-extended';

/**
 * Parameters for deriving a decryption key.
 * @typedef {Object} DeriveDecryptionKeyParams
 * @property {JweAlg} alg - The JWE algorithm to be used.
 * @property {JweEnc} enc - The encryption algorithm to be used.
 * @property {EcdhCurve} curve - The elliptic curve to be used for key derivation.
 * @property {Uint8Array} myPrivateKey - The private key of the recipient.
 * @property {Uint8Array | undefined} encryptedKey - The encrypted key, if applicable.
 * @property {JweHeaderParameters} protectedHeader - The protected header containing necessary parameters.
 */
export type EcdhesDeriveDecryptionKeyParams = {
  alg: JweAlg;
  enc: JweEnc;
  curve: EcdhCurve;
  myPrivateKey: Uint8Array;
  encryptedKey: Uint8Array | undefined;
  protectedHeader: JweHeaderParameters;
};

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
  const yourPublicKey = curve.toRawPublicKey(epk);

  const apu = decodeOptionalBase64Url({
    b64u: protectedHeader.apu,
    label: 'apu (Agreement PartyUInfo)',
  });
  const apv = decodeOptionalBase64Url({
    b64u: protectedHeader.apv,
    label: 'apv (Agreement PartyVInfo)',
  });

  if (apu) {
    validateJweApu(apu);
  }

  if (apv) {
    validateJweApv(apv);
  }

  enc = validateJweEnc(enc);

  const keyBitLength = cekBitLengthByEnc(enc);
  const sharedSecret = curve.getSharedSecret({
    privateKey: myPrivateKey,
    publicKey: yourPublicKey,
  });
  const otherInfo = buildKdfOtherInfo({
    algorithm: enc,
    apu,
    apv,
    keyBitLength,
  });

  return concatKdf({ sharedSecret, keyBitLength, otherInfo });
};
