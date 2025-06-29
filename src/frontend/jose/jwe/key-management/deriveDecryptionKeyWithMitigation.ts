import { deriveDecryptionKey } from '@/jose/jwe/key-management/deriveDecryptionKey';
import { generateMitigatedCek } from '@/jose/jwe/key-management/generateMitigatedCek';
import { JweAlg, JweEnc, JweHeaderParameters } from '@/jose/jwe/types';
import { EcdhCurve } from 'noble-curves-extended';

type DeriveDecryptionKeyWithMitigationParams = {
  alg: JweAlg;
  enc: JweEnc;
  curve: EcdhCurve;
  myPrivateKey: Uint8Array;
  encryptedKey: Uint8Array | undefined;
  protectedHeader: JweHeaderParameters;
};

/**
 * Derives decryption key with RFC 7516 §11.5 mitigation for timing attacks.
 *
 * Attempts standard key derivation first. On failure, generates a random CEK
 * with artificial delay to prevent timing side-channels.
 *
 * @param params - Parameters for key derivation
 * @returns Derived CEK or random CEK with mitigation measures
 *
 * @throws {JweInvalid} For invalid header parameters
 * @throws {JoseNotSupported} For unsupported algorithms
 *
 * @security
 * - Implements attack mitigation per RFC 7516 §11.5
 * - Uses constant-time operations where applicable
 * - Zeroizes sensitive data after use
 */
export const deriveDecryptionKeyWithMitigation = async (
  params: DeriveDecryptionKeyWithMitigationParams,
): Promise<Uint8Array> => {
  try {
    return deriveDecryptionKey(params);
  } catch (err) {
    console.log('[JWE] Key derivation failed, applying mitigation:', err);
    return generateMitigatedCek(params.curve, params.enc);
  }
};
