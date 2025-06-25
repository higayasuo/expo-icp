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

export interface JoseHeaderParameters {
  /** "kid" (Key ID) Header Parameter */
  kid?: string;

  /** "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter */
  x5t?: string;

  /** "x5c" (X.509 Certificate Chain) Header Parameter */
  x5c?: string[];

  /** "x5u" (X.509 URL) Header Parameter */
  x5u?: string;

  /** "jku" (JWK Set URL) Header Parameter */
  jku?: string;

  /** "jwk" (JSON Web Key) Header Parameter */
  jwk?: Jwk;

  /** "typ" (Type) Header Parameter */
  typ?: string;

  /** "cty" (Content Type) Header Parameter */
  cty?: string;
}

/** Shared Interface with a "crit" property for all sign, verify, encrypt and decrypt operations. */
export interface CritOption {
  /**
   * An object with keys representing recognized "crit" (Critical) Header Parameter names. The value
   * for those is either `true` or `false`. `true` when the Header Parameter MUST be integrity
   * protected, `false` when it's irrelevant.
   *
   * This makes the "Extension Header Parameter "..." is not recognized" error go away.
   *
   * Use this when a given JWS/JWT/JWE profile requires the use of proprietary non-registered "crit"
   * (Critical) Header Parameters. This will only make sure the Header Parameter is syntactically
   * correct when provided and that it is optionally integrity protected. It will not process the
   * Header Parameter in any way or reject the operation if it is missing. You MUST still verify the
   * Header Parameter was present and process it according to the profile's validation steps after
   * the operation succeeds.
   *
   * The JWS extension Header Parameter `b64` is always recognized and processed properly. No other
   * registered Header Parameters that need this kind of default built-in treatment are currently
   * available.
   */
  crit?: {
    [propName: string]: boolean;
  };
}
