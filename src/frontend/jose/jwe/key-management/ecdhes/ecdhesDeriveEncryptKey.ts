import {
  JweAlg,
  JweEnc,
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
} from '../../types';
import { buildKdfOtherInfo } from '@/jose/jwe/key-management/ecdhes/buildKdfOtherInfo';
import { concatKdf } from '@/jose/jwe/key-management/ecdhes/concatKdf';
import { encodeBase64Url } from 'u8a-utils';
import { cekBitLengthByEnc } from './cekBitLengthByEnc';
import { validateJweApu, validateJweApv } from '../../utils/validateJweApi';
import { validateJweEnc } from '../../utils/validateJweEnc';
import { EcdhCurve } from 'noble-curves-extended';

/**
 * Parameters for deriving an encryption key using ECDH-ES.
 * @typedef {Object} EcdhesDeriveEncryptionKeyParams
 * @property {JweAlg} alg - The JWE algorithm to be used.
 * @property {JweEnc} enc - The encryption algorithm to be used.
 * @property {EcdhCurve} curve - The elliptic curve to be used for key derivation.
 * @property {Uint8Array} yourPublicKey - The public key of the recipient.
 * @property {JweKeyManagementHeaderParameters | undefined} providedParameters - Optional parameters for key management.
 */
export type EcdhesDeriveEncryptionKeyParams = {
  alg: JweAlg;
  enc: JweEnc;
  curve: EcdhCurve;
  yourPublicKey: Uint8Array;
  providedParameters: JweKeyManagementHeaderParameters | undefined;
};

/**
 * Result of deriving an encryption key using ECDH-ES.
 * @typedef {Object} EcdhesDeriveEncryptionKeyResult
 * @property {Uint8Array} cek - The derived content encryption key.
 * @property {Uint8Array | undefined} [encryptedKey] - The encrypted key, if applicable.
 * @property {JweHeaderParameters} parameters - The JWE header parameters associated with the derived key.
 */
export type EcdhesDeriveEncryptionKeyResult = {
  cek: Uint8Array;
  encryptedKey?: Uint8Array;
  parameters: JweHeaderParameters;
};

/**
 * Derives an encryption key using ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) method.
 *
 * @param {EcdhesDeriveEncryptionKeyParams} params - The parameters required for deriving the encryption key.
 * @param {JweEnc} params.enc - The encryption algorithm to be used.
 * @param {EcdhCurve} params.curve - The elliptic curve to be used for key derivation.
 * @param {Uint8Array} params.yourPublicKey - The public key of the recipient.
 * @param {JweKeyManagementHeaderParameters | undefined} params.providedParameters - Optional parameters for key management.
 * @returns {EcdhesDeriveEncryptionKeyResult} The derived encryption key and associated parameters.
 */
export const ecdhesDeriveEncryptionKey = ({
  enc,
  curve,
  yourPublicKey,
  providedParameters,
}: EcdhesDeriveEncryptionKeyParams): EcdhesDeriveEncryptionKeyResult => {
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
