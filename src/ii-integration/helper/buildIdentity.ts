import { SignIdentity, PublicKey, Signature, fromHex } from '@dfinity/agent';
import { Ed25519PublicKey } from '@dfinity/identity';

/**
 * A class representing an identity that only has a public key and cannot sign.
 */
export class PublicKeyOnlyIdentity extends SignIdentity {
  #publicKey: PublicKey;

  /**
   * Creates an instance of PublicKeyOnlyIdentity.
   *
   * @param {PublicKey} publicKey - The public key for the identity.
   */
  constructor(publicKey: PublicKey) {
    super();
    this.#publicKey = publicKey;
  }

  /**
   * Returns the public key of the identity.
   *
   * @returns {PublicKey} The public key.
   */
  getPublicKey(): PublicKey {
    return this.#publicKey;
  }

  /**
   * Throws an error as this identity cannot sign.
   *
   * @param {ArrayBuffer} _blob - The data to sign.
   * @returns {Promise<Signature>} This method will always throw an error.
   * @throws {Error} Will always throw an error indicating that signing is not possible.
   */
  async sign(_blob: ArrayBuffer): Promise<Signature> {
    throw new Error('Cannot sign with public key only identity');
  }
}

/**
 * Builds an identity from a given public key string.
 *
 * @param {string} pubkey - The public key in hexadecimal format.
 * @returns {SignIdentity} The identity created from the public key.
 */
export const buildIdentity = (pubkey: string): SignIdentity => {
  return new PublicKeyOnlyIdentity(Ed25519PublicKey.fromDer(fromHex(pubkey)));
};
