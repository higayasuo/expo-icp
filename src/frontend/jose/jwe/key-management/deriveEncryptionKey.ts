import { EcdhCurve } from 'noble-curves-extended';
import {
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
  JweAlg,
  JweEnc,
} from '../types';
import { ecdhesDeriveEncryptionKey } from './ecdhes/ecdhesDeriveEncryptKey';
import { JweNotSupported } from '@/jose/errors/errors';

type DeriveEncryptionKeyParams = {
  alg: JweAlg;
  enc: JweEnc;
  curve: EcdhCurve;
  yourPublicKey: Uint8Array;
  providedParameters: JweKeyManagementHeaderParameters | undefined;
};

type DeriveEncryptionKeyResult = {
  cek: Uint8Array;
  encryptedKey?: Uint8Array;
  parameters: JweHeaderParameters;
};

export const deriveEncryptionKey = ({
  alg,
  enc,
  curve,
  yourPublicKey,
  providedParameters,
}: DeriveEncryptionKeyParams): DeriveEncryptionKeyResult => {
  if (alg === 'ECDH-ES') {
    return ecdhesDeriveEncryptionKey({
      alg,
      enc,
      curve,
      yourPublicKey,
      providedParameters,
    });
  }

  console.error(`Unsupported JWE Key Management Algorithm: ${alg}`);
  throw new JweNotSupported(`Unsupported JWE Key Management Algorithm`);
};
