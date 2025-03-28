var __classPrivateFieldSet = (this && this.__classPrivateFieldSet) || function (receiver, state, value, kind, f) {
    if (kind === "m") throw new TypeError("Private method is not writable");
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a setter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot write private member to an object whose class did not declare it");
    return (kind === "a" ? f.call(receiver, value) : f ? f.value = value : state.set(receiver, value)), value;
};
var __classPrivateFieldGet = (this && this.__classPrivateFieldGet) || function (receiver, state, kind, f) {
    if (kind === "a" && !f) throw new TypeError("Private accessor was defined without a getter");
    if (typeof state === "function" ? receiver !== state || !f : !state.has(receiver)) throw new TypeError("Cannot read private member from an object whose class did not declare it");
    return kind === "m" ? f : kind === "a" ? f.call(receiver) : f ? f.value : state.get(receiver);
};
var _PublicKeyOnlyIdentity_publicKey;
import { SignIdentity, fromHex } from '@dfinity/agent';
import { Ed25519PublicKey } from '@dfinity/identity';
/**
 * A class representing an identity that only has a public key and cannot sign.
 */
export class PublicKeyOnlyIdentity extends SignIdentity {
    /**
     * Creates an instance of PublicKeyOnlyIdentity.
     *
     * @param {PublicKey} publicKey - The public key for the identity.
     */
    constructor(publicKey) {
        super();
        _PublicKeyOnlyIdentity_publicKey.set(this, void 0);
        __classPrivateFieldSet(this, _PublicKeyOnlyIdentity_publicKey, publicKey, "f");
    }
    /**
     * Returns the public key of the identity.
     *
     * @returns {PublicKey} The public key.
     */
    getPublicKey() {
        return __classPrivateFieldGet(this, _PublicKeyOnlyIdentity_publicKey, "f");
    }
    /**
     * Throws an error as this identity cannot sign.
     *
     * @param {ArrayBuffer} _blob - The data to sign.
     * @returns {Promise<Signature>} This method will always throw an error.
     * @throws {Error} Will always throw an error indicating that signing is not possible.
     */
    async sign(_blob) {
        throw new Error('Cannot sign with public key only identity');
    }
}
_PublicKeyOnlyIdentity_publicKey = new WeakMap();
/**
 * Builds an identity from a given public key string.
 *
 * @param {string} pubkey - The public key in hexadecimal format.
 * @returns {SignIdentity} The identity created from the public key.
 */
export const buildIdentity = (pubkey) => {
    return new PublicKeyOnlyIdentity(Ed25519PublicKey.fromDer(fromHex(pubkey)));
};
