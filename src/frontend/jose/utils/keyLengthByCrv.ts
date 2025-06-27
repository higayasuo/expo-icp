import { JoseNotSupported } from '../errors';

/**
 * Returns the key length in bytes for a given curve.
 *
 * This function supports the following curves:
 * - P-256: 32 bytes
 * - P-384: 48 bytes
 * - P-521: 66 bytes
 * - secp256k1: 32 bytes
 * - Ed25519: 32 bytes
 * - X25519: 32 bytes
 *
 * @param {string} crv - The curve name.
 * @returns {number} The key length in bytes for the specified curve.
 * @throws {JoseNotSupported} If the specified curve is not supported.
 */
export const keyLengthByCrv = (crv: string): number => {
  switch (crv) {
    case 'P-256':
      return 32;
    case 'P-384':
      return 48;
    case 'P-521':
      return 66;
    case 'secp256k1':
      return 32;
    case 'Ed25519':
      return 32;
    case 'X25519':
      return 32;
    default:
      throw new JoseNotSupported(
        `The specified "crv" (Curve) is not supported: ${crv}`,
      );
  }
};
