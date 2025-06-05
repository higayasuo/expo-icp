/**
 * Parameters for ECDH shared secret calculation
 * @typedef {Object} ShareSecretParams
 * @property {Uint8Array} privateKey - The private key (32 bytes for P-256, 48 bytes for P-384, 66 bytes for P-521)
 * @property {Uint8Array} publicKey - The public key in uncompressed format (65 bytes for P-256, 97 bytes for P-384, 133 bytes for P-521)
 */
export type ShareSecretParams = {
  /** The private key (32 bytes for P-256, 48 bytes for P-384, 66 bytes for P-521) */
  privateKey: Uint8Array;
  /** The public key in uncompressed format (65 bytes for P-256, 97 bytes for P-384, 133 bytes for P-521) */
  publicKey: Uint8Array;
};

/**
 * A function that calculates a shared secret using ECDH
 * @param {ShareSecretParams} params - The parameters for shared secret calculation
 * @returns {Promise<Uint8Array>} The raw shared secret (32 bytes for P-256, 48 bytes for P-384, 66 bytes for P-521)
 */
export type ShareSecret = (params: ShareSecretParams) => Promise<Uint8Array>;
