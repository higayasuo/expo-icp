import { NistCurve } from 'noble-curves-extended';
import { JweAlg, JweHeaderParameters } from '../types';
import { ecdhesManageDecryptKey } from './ecdhesManageDecryptKey';

export type ManageDecryptKeyParams = {
  alg: JweAlg;
  curve: NistCurve;
  myPrivateKey: Uint8Array;
  encryptedKey: Uint8Array | undefined;
  protectedHeader: JweHeaderParameters;
};

export const manageDecryptKey = (
  params: ManageDecryptKeyParams,
): Uint8Array => {
  const { alg } = params;

  if (alg === 'ECDH-ES') {
    return ecdhesManageDecryptKey(params);
  }

  throw new Error(`Unsupported JWE Algorithm: ${alg}`);
};
