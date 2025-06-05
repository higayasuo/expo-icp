import { Jwk } from '@/jose/types';

/**
 * Parameters for JWE (JSON Web Encryption) key management headers
 * @typedef {Object} JWEKeyManagementHeaderParameters
 * @property {Uint8Array} [apu] - Agreement PartyUInfo - Optional information about the producer
 * @property {Uint8Array} [apv] - Agreement PartyVInfo - Optional information about the recipient
 */
export type JweKeyManagementHeaderParameters = {
  /** Agreement PartyUInfo - Optional information about the producer */
  apu?: Uint8Array;
  /** Agreement PartyVInfo - Optional information about the recipient */
  apv?: Uint8Array;
};

/**
 * Parameters for JWE (JSON Web Encryption) headers
 * @typedef {Object} JWEHeaderParameters
 * @property {string} [apu] - Base64url-encoded Agreement PartyUInfo - Optional information about the producer
 * @property {string} [apv] - Base64url-encoded Agreement PartyVInfo - Optional information about the recipient
 * @property {Jwk} [epk] - Ephemeral Public Key - Optional ephemeral public key for key agreement
 */
export type JweHeaderParameters = {
  /** Base64url-encoded Agreement PartyUInfo - Optional information about the producer */
  apu?: string;
  /** Base64url-encoded Agreement PartyVInfo - Optional information about the recipient */
  apv?: string;
  /** Ephemeral Public Key - Optional ephemeral public key for key agreement */
  epk?: Jwk;
};
