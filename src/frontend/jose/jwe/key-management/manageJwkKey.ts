import { NistCurve } from 'noble-curves-extended';
import {
  JweHeaderParameters,
  JweKeyManagementHeaderParameters,
} from '../types';
import { ecdhesManageJwkKey } from './ecdhesManageJwkKey';

/**
 * Parameters for managing JWK key
 * @typedef {Object} ManageJwkKeyParams
 * @property {string} alg - Algorithm identifier
 * @property {string} enc - Encryption algorithm identifier
 * @property {NistCurve} curve - Elliptic curve implementation
 * @property {Uint8Array} myPrivateKey - Private key bytes
 * @property {Uint8Array} yourPublicKey - Public key bytes
 * @property {JweKeyManagementHeaderParameters} providedParameters - Key management header parameters
 */
export type ManageJwkKeyParams = {
  alg: string;
  enc: string;
  curve: NistCurve;
  myPrivateKey?: Uint8Array;
  yourPublicKey: Uint8Array;
  providedParameters: JweKeyManagementHeaderParameters;
};

/**
 * Result of managing JWK key
 * @typedef {Object} ManageJwkKeyResult
 * @property {Uint8Array} cek - Content Encryption Key
 * @property {Uint8Array} [encryptedKey] - Encrypted key (optional)
 * @property {JweHeaderParameters} parameters - JWE header parameters
 */
export type ManageJwkKeyResult = {
  cek: Uint8Array;
  encryptedKey?: Uint8Array;
  parameters: JweHeaderParameters;
};

/**
 * Manages JWK key based on the specified algorithm
 * @param {ManageJwkKeyParams} params - Parameters for key management
 * @returns {ManageJwkKeyResult} - Result containing CEK, encrypted key, and header parameters
 * @throws {Error} If the algorithm is not supported
 */
export const manageJwkKey = (
  params: ManageJwkKeyParams,
): ManageJwkKeyResult => {
  const { alg } = params;

  if (alg === 'ECDH-ES') {
    return ecdhesManageJwkKey(params);
  }

  throw new Error(`Unsupported JWE Algorithm: ${alg}`);
};
