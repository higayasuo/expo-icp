import { JweHeaderParameters } from '../types';
import {
  ManageEncryptKeyParams,
  ManageEncryptKeyResult,
} from './manageEncryptKey';
import { buildKdfOtherInfo } from '@/jose/jwe/key-management/ecdhes/buildKdfOtherInfo';
import { concatKdf } from '@/jose/jwe/key-management/ecdhes/concatKdf';
import { toB64U } from 'u8a-utils';
import { cekBitLengthByEnc } from '../utils/cekBitLengthByEnc';

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
  const cek = concatKdf({ sharedSecret, keyBitLength, otherInfo });

  return { cek, encryptedKey: undefined, parameters };
};
