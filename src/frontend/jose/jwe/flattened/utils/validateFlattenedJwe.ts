import { isPlainObject } from '@/jose/utils/isPlainObject';
import { FlattenedJwe, JweHeaderParameters } from '../../types';
import { JweInvalid } from '@/jose/errors/errors';
import { mergeJweHeaders } from './mergeJweHeaders';
import {
  decodeJweOptionalBase64Url,
  decodeJweRequiredBase64Url,
} from '@/jose/utils/decodeBase64Url';
import { parseJweProtected } from './parseJweProtected';

/**
 * Represents the validated components of a Flattened JWE structure
 */
type ValidateFlattenedJweResult = {
  /** Initialization Vector as Uint8Array */
  iv: Uint8Array;
  /** Ciphertext as Uint8Array */
  ciphertext: Uint8Array;
  /** Authentication Tag as Uint8Array */
  tag: Uint8Array;
  /** Optional Encrypted Key as Uint8Array */
  encryptedKey: Uint8Array | undefined;
  /** Optional Additional Authenticated Data as Uint8Array */
  aad: Uint8Array | undefined;
  /** Combined JOSE header parameters */
  joseHeader: JweHeaderParameters;
  /** Parsed protected header parameters */
  parsedProtected: JweHeaderParameters;
};

/**
 * Validates and decodes a Flattened JWE structure
 * @param {FlattenedJwe} jwe - The Flattened JWE object to validate
 * @returns {ValidateFlattenedJweResult} - The validated and decoded JWE components
 * @throws {JweInvalid} - If the JWE structure is invalid
 */
export const validateFlattenedJwe = (
  jwe: FlattenedJwe,
): ValidateFlattenedJweResult => {
  if (!isPlainObject(jwe)) {
    throw new JweInvalid('Flattened JWE must be an object');
  }

  const iv = decodeJweRequiredBase64Url({
    b64u: jwe.iv,
    label: 'JWE Initialization Vector',
  });

  const ciphertext = decodeJweRequiredBase64Url({
    b64u: jwe.ciphertext,
    label: 'JWE Ciphertext',
  });

  const tag = decodeJweRequiredBase64Url({
    b64u: jwe.tag,
    label: 'JWE Authentication Tag',
  });

  const encryptedKey = decodeJweOptionalBase64Url({
    b64u: jwe.encrypted_key,
    label: 'JWE Encrypted Key',
  });

  const aad = decodeJweOptionalBase64Url({
    b64u: jwe.aad,
    label: 'JWE Additional Authenticated Data',
  });

  if (jwe.header !== undefined && !isPlainObject(jwe.header)) {
    throw new JweInvalid('JWE Per-Recipient Unprotected Header is invalid');
  }

  if (jwe.unprotected !== undefined && !isPlainObject(jwe.unprotected)) {
    throw new JweInvalid('JWE Shared Unprotected Header is invalid');
  }

  const parsedProtected = parseJweProtected(jwe.protected);

  const joseHeader = mergeJweHeaders({
    protectedHeader: parsedProtected,
    sharedUnprotectedHeader: jwe.unprotected,
    unprotectedHeader: jwe.header,
  });

  return {
    iv,
    ciphertext,
    tag,
    encryptedKey,
    aad,
    joseHeader,
    parsedProtected,
  };
};
