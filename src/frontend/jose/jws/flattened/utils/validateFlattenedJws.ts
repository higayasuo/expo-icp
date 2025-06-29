import { isPlainObject } from '@/jose/utils/isPlainObject';
import { JwsHeaderParameters } from '@/jose/jws/types';
import { FlattenedJwsInput } from '../types';
import { JwsInvalid } from '@/jose/errors/errors';
import { mergeJwsHeaders } from './mergeJwsHeaders';
import { decodeRequiredBase64Url } from '@/jose/utils/decodeBase64Url';
import { parseBase64UrlHeader } from '@/jose/utils/parseBase64UrlHeader';
import { isUint8Array } from 'u8a-utils';

/**
 * Represents the validated components of a Flattened JWS structure
 */
type ValidateFlattenedJwsResult = {
  /** Signature as Uint8Array */
  signature: Uint8Array;
  /** Combined JOSE header parameters */
  joseHeader: JwsHeaderParameters;
  /** Parsed protected header parameters */
  parsedProtected: JwsHeaderParameters;
};

/**
 * Validates and decodes a Flattened JWS structure
 * @param jws - The Flattened JWS object to validate
 * @returns {ValidateFlattenedJwsResult} - The validated and decoded JWS components
 * @throws {JwsInvalid} - If the JWS structure is invalid
 */
export const validateFlattenedJws = (
  jws: FlattenedJwsInput,
): ValidateFlattenedJwsResult => {
  if (jws == null) {
    throw new JwsInvalid('Flattened JWS is missing');
  }

  if (!isPlainObject(jws)) {
    throw new JwsInvalid('Flattened JWS must be a plain object');
  }

  const signature = decodeRequiredBase64Url({
    b64u: jws.signature,
    label: 'JWS Signature',
  });

  if (jws.header !== undefined && !isPlainObject(jws.header)) {
    throw new JwsInvalid('JWS Unprotected Header is invalid');
  }

  const parsedProtected = parseBase64UrlHeader<JwsHeaderParameters>(
    jws.protected,
    'JWS Protected Header',
  );

  const joseHeader = mergeJwsHeaders({
    protectedHeader: parsedProtected,
    unprotectedHeader: jws.header,
  });

  if (jws.payload == null) {
    throw new JwsInvalid('JWS Payload is missing');
  }

  if (typeof jws.payload !== 'string' && !isUint8Array(jws.payload)) {
    throw new JwsInvalid('JWS Payload must be a string or Uint8Array');
  }

  return {
    signature,
    joseHeader,
    parsedProtected,
  };
};
