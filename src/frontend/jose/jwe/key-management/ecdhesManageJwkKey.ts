import { JweHeaderParameters } from '../types';
import { ManageJwkKeyParams, ManageJwkKeyResult } from './manageJwkKey';
import { buildKdfOtherInfo } from '@/jose/ecdhes/buildKdfOtherInfo';
import { keyBitLengthByEnc } from '../utils/keyBitLengthByEnc';
import { concatKdf } from '@/jose/ecdhes/concatKdf';
import { toB64U } from 'u8a-utils';

/**
 * Manages JWK key for ECDH-ES (Elliptic Curve Diffie-Hellman Ephemeral Static) key agreement
 * @param {ManageJwkKeyParams} params - Parameters for key management
 * @param {string} params.alg - Algorithm identifier (should be 'ECDH-ES')
 * @param {string} params.enc - Encryption algorithm identifier
 * @param {NistCurve} params.curve - Elliptic curve implementation
 * @param {Uint8Array} params.privateKey - Private key bytes
 * @param {Uint8Array} params.publicKey - Public key bytes
 * @param {JweKeyManagementHeaderParameters} params.providedParameters - Key management header parameters
 * @returns {ManageJwkKeyResult} - Result containing CEK, encrypted key (undefined for ECDH-ES), and header parameters
 * @throws {Error} If the encryption algorithm is not supported
 */
export const ecdhesManageJwkKey = ({
  enc,
  curve,
  privateKey,
  publicKey,
  providedParameters,
}: ManageJwkKeyParams): ManageJwkKeyResult => {
  const { apu, apv } = providedParameters;
  const myPublicKey = curve.getPublicKey(privateKey, false);
  const epk = curve.toJwkPublicKey(myPublicKey);
  const parameters: JweHeaderParameters = { epk };
  if (apu) {
    parameters.apu = toB64U(apu);
  }
  if (apv) {
    parameters.apv = toB64U(apv);
  }

  const keyBitLength = keyBitLengthByEnc(enc);
  const sharedSecret = curve
    .getSharedSecret(privateKey, publicKey, true)
    .slice(1);
  const otherInfo = buildKdfOtherInfo({
    algorithm: enc,
    apu,
    apv,
    keyBitLength,
  });
  const cek = concatKdf({ sharedSecret, keyBitLength, otherInfo });

  return { cek, encryptedKey: undefined, parameters };
};
