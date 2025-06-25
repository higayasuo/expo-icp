import { JweHeaderParameters } from '../types';
import {
  DeriveEncryptionKeyParams,
  DeriveEncryptionKeyResult,
} from './deriveEncryptionKey';
import { buildKdfOtherInfo } from '@/jose/jwe/key-management/ecdhes/buildKdfOtherInfo';
import { concatKdf } from '@/jose/jwe/key-management/ecdhes/concatKdf';
import { encodeBase64Url } from 'u8a-utils';
import { cekBitLengthByEnc } from '../utils/cekBitLengthByEnc';
import { validateJweApu, validateJweApv } from '../utils/validateJweApi';
import { validateJweEnc } from '../utils/validateJweEnc';

/**
 * Derives an encryption key using ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) method.
 *
 * @param {DeriveEncryptionKeyParams} params - The parameters required for deriving the encryption key.
 * @param {JweEnc} params.enc - The encryption algorithm to be used.
 * @param {EcdhCurve} params.curve - The elliptic curve to be used for key derivation.
 * @param {Uint8Array} params.yourPublicKey - The public key of the recipient.
 * @param {JweKeyManagementHeaderParameters | undefined} params.providedParameters - Optional parameters for key management.
 * @returns {DeriveEncryptionKeyResult} The derived encryption key and associated parameters.
 */
export const ecdhesDeriveEncryptionKey = ({
  enc,
  curve,
  yourPublicKey,
  providedParameters,
}: DeriveEncryptionKeyParams): DeriveEncryptionKeyResult => {
  const myPrivateKey = curve.randomPrivateKey();
  const myPublicKey = curve.getPublicKey(myPrivateKey);
  const epk = curve.toJwkPublicKey(myPublicKey);
  const parameters: JweHeaderParameters = { epk };

  const apu = validateJweApu(providedParameters?.apu);
  const apv = validateJweApv(providedParameters?.apv);
  if (apu) {
    parameters.apu = encodeBase64Url(apu);
  }
  if (apv) {
    parameters.apv = encodeBase64Url(apv);
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
  const cek = concatKdf({ sharedSecret, keyBitLength, otherInfo });

  return { cek, encryptedKey: undefined, parameters };
};
