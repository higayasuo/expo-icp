import { JweAlg, JweHeaderParameters, JweEnc } from '@/jose/jwe/types';

/** Recognized Compact JWE Header Parameters, any other Header Members may also be present. */
export interface CompactJweHeaderParameters extends JweHeaderParameters {
  alg: JweAlg;
  enc: JweEnc;
}

/** Compact JWE decryption result */
export interface CompactDecryptResult {
  /** Plaintext. */
  plaintext: Uint8Array;

  /** JWE Protected Header. */
  protectedHeader: CompactJweHeaderParameters;
}
