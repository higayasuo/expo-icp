import {
  RandomBytes,
  JwkPublicKey,
  createSignatureCurve,
} from 'noble-curves-extended';
import { FlattenedJwsInput, FlattenedVerifyResult } from './types';
import { VerifyOptions } from '@/jose/jws/types';
import { JwsInvalid, JwsSignatureVerificationFailed } from '@/jose/errors';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { validateFlattenedJws } from './utils/validateFlattenedJws';
import { validateCrit } from '@/jose/utils/validateCrit';
import { parseB64 } from './utils/parseB64';
import { validateJwsAlg } from '../utils/validateJwsAlg';
import { encodeVerifyTarget } from './utils/encodeVerifyTarget';
import { getErrorMessage } from '@/jose/utils/getErrorMessage';

/**
 * Verifier for Flattened JWS (JSON Web Signature) according to RFC 7515
 *
 * This class provides functionality to verify JWS signatures in flattened serialization format.
 * It supports various signature algorithms and handles both b64=true and b64=false payload encoding
 * as specified in RFC 7797.
 *
 * @example
 * ```typescript
 * const result = new FlattenedVerifier(randomBytes).verify(
 *   {
 *     protected: "eyJhbGciOiJFUzI1NiJ9",
 *     payload: "SGVsbG8sIFdvcmxkIQ",
 *     signature: "signature_bytes"
 *   },
 *   {
 *     kty: "EC",
 *     crv: "P-256",
 *     x: "base64url_x_coordinate",
 *     y: "base64url_y_coordinate"
 *   }
 * );
 *
 * console.log(result.payload); // Decoded payload
 * console.log(result.protectedHeader); // Parsed protected header
 * ```
 */
export class FlattenedVerifier {
  #randomBytes: RandomBytes;

  /**
   * Creates a new FlattenedVerifier instance
   *
   * @param randomBytes - Cryptographically secure random bytes generator
   */
  constructor(randomBytes: RandomBytes) {
    this.#randomBytes = randomBytes;
  }

  /**
   * Verifies a Flattened JWS signature
   *
   * This method validates the JWS signature and returns the decoded payload along with
   * parsed headers. It performs the following steps:
   * 1. Validates input parameters
   * 2. Creates signature curve from JWK
   * 3. Validates JWS structure and headers
   * 4. Constructs verification target
   * 5. Verifies signature
   * 6. Returns decoded payload and headers
   *
   * @param jws - The Flattened JWS object to verify
   * @param jwkPublicKey - The JWK public key for signature verification
   * @param options - Optional verification options including critical parameter handling
   *
   * @returns A promise that resolves to the verification result containing payload and headers
   *
   * @throws {JwsInvalid} When JWS structure is invalid, JWK is malformed, or verification fails
   * @throws {JwsSignatureVerificationFailed} When signature verification fails
   *
   * @example
   * ```typescript
   * const result = new FlattenedVerifier(randomBytes).verify(
   *   {
   *     protected: "eyJhbGciOiJFUzI1NiIsImJ2IjoiUyIsImN0eSI6IkpXVCJ9",
   *     payload: "eyJpc3MiOiJqb2UiLCJhdWQiOiJodHRwczovL2p3dC5pbyIsInN1YiI6IjEyMzQ1Njc4OTAiLCJuYmYiOjE0NDQ0Nzg0MDAsImV4cCI6MTQ0NDQ4MjAwMCwiaWF0IjoxNDQ0NDc4NDAwfQ",
   *     signature: "signature_bytes_here"
   *   },
   *   {
   *     kty: "EC",
   *     crv: "P-256",
   *     x: "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
   *     y: "x_FEzRu9m36HLN_tue659LNpXW6pCSten6ESqXqZ4Qo"
   *   }
   * );
   *
   * console.log(result.payload); // Decoded JWT payload
   * console.log(result.protectedHeader); // { alg: "ES256", b64: "S", cty: "JWT" }
   * ```
   *
   * @example
   * ```typescript
   * // With custom critical parameter handling
   * const result = new FlattenedVerifier(randomBytes).verify(jws, jwk, {
   *   crit: ["b64", "custom-param"]
   * });
   * ```
   */
  verify = async (
    jws: FlattenedJwsInput,
    jwkPublicKey: JwkPublicKey,
    options?: VerifyOptions,
  ): Promise<FlattenedVerifyResult> => {
    if (jws == null) {
      throw new JwsInvalid('Flattened JWS is missing');
    }

    if (!isPlainObject(jws)) {
      throw new JwsInvalid('Flattened JWS must be a plain object');
    }

    if (jwkPublicKey == null) {
      throw new JwsInvalid('jwkPublicKey is missing');
    }

    if (!isPlainObject(jwkPublicKey)) {
      throw new JwsInvalid('jwkPublicKey must be a plain object');
    }

    if (!jwkPublicKey.crv) {
      throw new JwsInvalid('jwkPublicKey.crv is missing');
    }

    try {
      const signatureCurve = createSignatureCurve(
        jwkPublicKey.crv,
        this.#randomBytes,
      );
      const publicKey = signatureCurve.toRawPublicKey(jwkPublicKey);

      const { signature, joseHeader, parsedProtected } =
        validateFlattenedJws(jws);

      const criticalParamNames = validateCrit({
        Err: JwsInvalid,
        recognizedDefault: { b64: true },
        recognizedOption: options?.crit,
        protectedHeader: parsedProtected,
        joseHeader,
      });

      const b64 = parseB64(parsedProtected.b64, criticalParamNames);
      validateJwsAlg(
        parsedProtected.alg,
        signatureCurve.signatureAlgorithmName,
      );

      const { verifyTarget, payload } = encodeVerifyTarget({
        protectedHeaderB64U: jws.protected ?? '',
        payload: jws.payload,
        b64,
      });

      const verified = signatureCurve.verify({
        publicKey,
        message: verifyTarget,
        signature,
      });

      if (!verified) {
        throw new JwsSignatureVerificationFailed();
      }

      const result: FlattenedVerifyResult = { payload };

      if (jws.protected !== undefined) {
        result.protectedHeader = parsedProtected;
      }

      if (jws.header !== undefined) {
        result.unprotectedHeader = jws.header;
      }

      return result;
    } catch (error) {
      if (error instanceof JwsSignatureVerificationFailed) {
        throw error;
      }
      console.log(getErrorMessage(error));

      throw new JwsInvalid('Failed to verify JWS signature');
    }
  };
}
