import { JweHeaderParameters } from '../types';
import {
  ManageEncryptKeyParams,
  ManageEncryptKeyResult,
} from './manageEncryptKey';
import { buildKdfOtherInfo } from '@/jose/ecdhes/buildKdfOtherInfo';
import { keyBitLengthByEnc } from '../utils/keyBitLengthByEnc';
import { concatKdf } from '@/jose/ecdhes/concatKdf';
import { toB64U } from 'u8a-utils';

export const ecdhesManageEncryptKey = ({
  enc,
  curve,
  yourPublicKey,
  providedParameters,
}: ManageEncryptKeyParams): ManageEncryptKeyResult => {
  const myPrivateKey = curve.utils.randomPrivateKey();
  const myPublicKey = curve.getPublicKey(myPrivateKey, false);
  const epk = curve.toJwkPublicKey(myPublicKey);
  const parameters: JweHeaderParameters = { epk };

  const { apu, apv } = providedParameters ?? {};
  if (apu) {
    parameters.apu = toB64U(apu);
  }
  if (apv) {
    parameters.apv = toB64U(apv);
  }

  const keyBitLength = keyBitLengthByEnc(enc);
  const sharedSecret = curve
    .getSharedSecret(myPrivateKey, yourPublicKey, true)
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
