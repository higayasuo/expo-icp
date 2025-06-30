/**
 * Error codes for JOSE related errors
 */
export type ErrorCode =
  | 'ERR_JOSE_GENERIC'
  | 'ERR_JOSE_INVALID'
  | 'ERR_JOSE_NOT_SUPPORTED'
  | 'ERR_JWE_INVALID'
  | 'ERR_JWE_NOT_SUPPORTED'
  | 'ERR_JWS_INVALID'
  | 'ERR_JWS_NOT_SUPPORTED'
  | 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED';

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

/**
 * Error thrown when JOSE is invalid
 */
export class JoseInvalid extends AbstractJoseError {
  readonly code = 'ERR_JOSE_INVALID' as const;
}

/**
 * Error thrown when JOSE is not supported
 */
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
 * Error thrown when a JWE (JSON Web Encryption) feature is not supported
 */
export class JweNotSupported extends AbstractJoseError {
  readonly code = 'ERR_JWE_NOT_SUPPORTED' as const;
}

/**
 * Error thrown when JWS (JSON Web Signature) is invalid
 */
export class JwsInvalid extends AbstractJoseError {
  readonly code = 'ERR_JWS_INVALID' as const;
}

/**
 * Error thrown when a JWS (JSON Web Signature) feature is not supported
 */
export class JwsNotSupported extends AbstractJoseError {
  readonly code = 'ERR_JWS_NOT_SUPPORTED' as const;
}

export class JwsSignatureVerificationFailed extends AbstractJoseError {
  readonly code = 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' as const;

  /** @ignore */
  constructor(
    message = 'JWS signature verification failed',
    options?: { cause?: unknown },
  ) {
    super(message, options);
  }
}
