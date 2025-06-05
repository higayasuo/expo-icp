import { NistCurveName } from 'noble-curves-extended';

/**
 * Represents a JSON Web Key (JWK) for elliptic curve cryptography
 * @typedef {Object} Jwk
 * @property {string} kty - Key type, must be "EC" for elliptic curve keys
 * @property {string} crv - Curve name (e.g., "P-256", "P-384", "P-521")
 * @property {string} x - Base64url-encoded x-coordinate of the public key
 * @property {string} [y] - Base64url-encoded y-coordinate of the public key (optional for some key types)
 */
export type Jwk = {
  kty: string;
  crv: string;
  x: string;
  y?: string;
};

export type CurveName = NistCurveName;
