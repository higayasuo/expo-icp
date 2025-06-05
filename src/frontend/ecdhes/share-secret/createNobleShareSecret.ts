import { ShareSecret } from '../types';
import { CurveFnWithCreate } from 'noble-curves-extended';

/**
 * Creates a function that calculates a shared secret using noble-curves-extended
 * @param {CurveFnWithCreate} curve - The curve implementation from noble-curves-extended
 * @returns {ShareSecret} - A function that calculates the shared secret
 */
export const createNobleShareSecret =
  (curve: CurveFnWithCreate): ShareSecret =>
  /**
   * Calculates a shared secret using ECDH
   * @param {ShareSecretParams} params - The parameters for shared secret calculation
   * @param {Uint8Array} params.privateKey - The private key
   * @param {Uint8Array} params.publicKey - The public key in uncompressed format
   * @returns {Promise<Uint8Array>} The raw shared secret (32 bytes for P-256, 48 bytes for P-384, 66 bytes for P-521)
   */
  async ({ privateKey, publicKey }): Promise<Uint8Array> => {
    const sharedSecret = curve.getSharedSecret(privateKey, publicKey, true);
    return sharedSecret.slice(1);
  };
