import { EcdhCurve } from 'noble-curves-extended';
import { JweAlg, JweEnc, JweHeaderParameters } from '../types';
import { ecdhesDeriveDecryptionKey } from './ecdhesDriveDecryptionKey';
import { JweNotSupported } from '@/jose/errors/errors';

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
export type DeriveDecryptionKeyParams = {
  alg: JweAlg;
  enc: JweEnc;
  curve: EcdhCurve;
  myPrivateKey: Uint8Array;
  encryptedKey: Uint8Array | undefined;
  protectedHeader: JweHeaderParameters;
};

/**
 * Derives a decryption key based on the specified parameters.
 *
 * @param {DeriveDecryptionKeyParams} params - The parameters required for deriving the decryption key.
 * @returns {Uint8Array} The derived decryption key.
 * @throws {JweNotSupported} If the JWE key management algorithm is not supported.
 */
export const deriveDecryptionKey = ({
  alg,
  enc,
  curve,
  myPrivateKey,
  encryptedKey,
  protectedHeader,
}: DeriveDecryptionKeyParams): Uint8Array => {
  if (alg === 'ECDH-ES') {
    return ecdhesDeriveDecryptionKey({
      alg,
      enc,
      curve,
      myPrivateKey,
      encryptedKey,
      protectedHeader,
    });
  }

  console.error(`Unsupported JWE key management algorithm: ${alg}`);
  throw new JweNotSupported('Unsupported JWE key management algorithm');
};
