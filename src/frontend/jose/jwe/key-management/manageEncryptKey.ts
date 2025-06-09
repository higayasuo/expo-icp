import { NistCurve } from 'noble-curves-extended';
import {
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
} from '../types';
import { ecdhesManageEncryptKey } from './ecdhesManageEncryptKey';

/**
 * Parameters for managing encryption key
 * @typedef {Object} ManageEncryptKeyParams
 * @property {string} alg - JWE Algorithm identifier
 * @property {string} enc - JWE Encryption Algorithm identifier
 * @property {NistCurve} curve - Elliptic curve implementation
 * @property {Uint8Array} yourPublicKey - Recipient's public key
 * @property {JweKeyManagementHeaderParameters} providedParameters - Key management header parameters
 */
export type ManageEncryptKeyParams = {
  alg: string;
  enc: string;
  curve: NistCurve;
  yourPublicKey: Uint8Array;
  providedParameters: JweKeyManagementHeaderParameters | undefined;
};

/**
 * Result of managing encryption key
 * @typedef {Object} ManageEncryptKeyResult
 * @property {Uint8Array} cek - Content Encryption Key
 * @property {Uint8Array} [encryptedKey] - Encrypted key (optional)
 * @property {JweHeaderParameters} parameters - JWE header parameters
 */
export type ManageEncryptKeyResult = {
  cek: Uint8Array;
  encryptedKey?: Uint8Array;
  parameters: JweHeaderParameters;
};

/**
 * Manages encryption key based on the specified JWE algorithm
 *
 * This function handles key management for JWE encryption by:
 * - Selecting appropriate key management algorithm based on 'alg' parameter
 * - Generating or processing encryption keys
 * - Returning necessary components for JWE encryption
 *
 * @param {ManageEncryptKeyParams} params - Parameters for key management
 * @returns {ManageEncryptKeyResult} - Result containing CEK, encrypted key, and header parameters
 * @throws {Error} If the algorithm is not supported
 */
export const manageEncryptKey = (
  params: ManageEncryptKeyParams,
): ManageEncryptKeyResult => {
  const { alg } = params;

  if (alg === 'ECDH-ES') {
    return ecdhesManageEncryptKey(params);
  }

  throw new Error(`Unsupported JWE Algorithm: ${alg}`);
};
