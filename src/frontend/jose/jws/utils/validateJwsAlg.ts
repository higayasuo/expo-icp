import { JwsInvalid, JwsNotSupported } from '@/jose/errors';
import { JwsAlg } from '@/jose/jws/types';
import { isJwsAlg } from './isJwsAlg';

const INVALID_ERROR_MESSAGE = '"alg" (Algorithm) is invalid';
const NOT_SUPPORTED_ERROR_MESSAGE =
  'The specified "alg" (Algorithm) is not supported';

export const validateJwsAlg = (alg: unknown): JwsAlg => {
  if (!alg) {
    console.error('"alg" (Key Management Algorithm) is missing');
    throw new JweInvalid(INVALID_ERROR_MESSAGE);
  }

  if (typeof alg !== 'string') {
    console.error('"alg" (Key Management Algorithm) must be a string');
    throw new JwsInvalid(INVALID_ERROR_MESSAGE);
  }

  if (!isJwsAlg(alg)) {
    console.error(
      `The specified "alg" (Key Management Algorithm) is not supported: ${alg}. Only "ECDH-ES" is supported.`,
    );
    throw new JweNotSupported(NOT_SUPPORTED_ERROR_MESSAGE);
  }

  return alg;
};
