import { PublicKey, fromHex } from '@dfinity/agent';
import { Ed25519PublicKey } from '@dfinity/identity';

/**
 * Converts a hexadecimal public key string to an Ed25519PublicKey.
 *
 * @param {string} pubkey - The hexadecimal string representation of the public key.
 * @returns {PublicKey} The Ed25519 public key.
 */
export const buildAppPublicKey = (pubkey: string): PublicKey => {
  return Ed25519PublicKey.fromDer(fromHex(pubkey));
};
