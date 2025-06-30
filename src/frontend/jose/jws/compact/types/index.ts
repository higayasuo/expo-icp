import { JwsHeaderParameters, JwsAlg } from '@/jose/jws/types';

/** Recognized Compact JWS Header Parameters, any other Header Members may also be present. */
export interface CompactJwsHeaderParameters extends JwsHeaderParameters {
  alg: JwsAlg;
}

/** Compact JWS verification result */
export interface CompactVerifyResult {
  /** JWS Payload. */
  payload: Uint8Array;

  /** JWS Protected Header. */
  protectedHeader: CompactJwsHeaderParameters;
}
