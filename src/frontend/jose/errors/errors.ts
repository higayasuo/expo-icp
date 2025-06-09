/**
 * Error codes for JOSE related errors
 */
export type ErrorCode =
  | 'ERR_JOSE_GENERIC'
  | 'ERR_JOSE_NOT_SUPPORTED'
  | 'ERR_JWE_INVALID'
  | 'ERR_JWS_INVALID';

/**
 * Abstract base class for JOSE related errors
 */
export abstract class AbstractJoseError extends Error {
  /**
   * The error code for this error
   */
  abstract readonly code: ErrorCode;

  /**
   * Creates a new AbstractJoseError instance
   * @param message - The error message
   * @param options - Optional error options including cause
   */
  constructor(message?: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = this.constructor.name;
    Error.captureStackTrace?.(this, this.constructor);
  }
}

/**
 * Generic JOSE error
 */
export class JoseGeneric extends AbstractJoseError {
  readonly code = 'ERR_JOSE_GENERIC' as const;
}

export class JoseNotSupported extends AbstractJoseError {
  readonly code = 'ERR_JOSE_NOT_SUPPORTED' as const;
}

/**
 * Error thrown when JWE (JSON Web Encryption) is invalid
 */
export class JweInvalid extends AbstractJoseError {
  readonly code = 'ERR_JWE_INVALID' as const;
}

/**
 * Error thrown when JWS (JSON Web Signature) is invalid
 */
export class JwsInvalid extends AbstractJoseError {
  readonly code = 'ERR_JWS_INVALID' as const;
}
