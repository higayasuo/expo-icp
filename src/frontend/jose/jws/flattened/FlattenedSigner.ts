/**
 * Signing JSON Web Signature (JWS) in Flattened JSON Serialization
 *
 * @module
 */

import { encodeBase64Url, isUint8Array } from 'u8a-utils';

import { JweInvalid, JwsInvalid } from '@/jose/errors/errors';
import { validateCrit } from '@/jose/utils/validateCrit';
import {
  createSignatureCurve,
  JwkPrivateKey,
  RandomBytes,
} from 'noble-curves-extended';
import { JwsHeaderParameters, SignOptions } from '../types';
import { FlattenedJws } from './types';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { mergeJwsHeaders } from './utils/mergeJwsHeaders';
import { parseB64 } from './utils/parseB64';
import { validateJwsAlg } from '@/jose/jws/utils/validateJwsAlg';
import { encodeSignTarget } from './utils/encodeSignTarget';
import { getErrorMessage } from '@/jose/utils/getErrorMessage';

/**
 * Class representing a signer for JSON Web Signatures (JWS) in Flattened JSON Serialization.
 */
export class FlattenedSigner {
  #randomBytes: RandomBytes;

  #protectedHeader: JwsHeaderParameters | undefined;

  #unprotectedHeader: JwsHeaderParameters | undefined;

  /**
   * Creates an instance of FlattenedSigner.
   *
   * @param {RandomBytes} randomBytes - A function to generate random bytes.
   */
  constructor(randomBytes: RandomBytes) {
    this.#randomBytes = randomBytes;
  }

  /**
   * Sets the protected header for the JWS.
   *
   * @param {JwsHeaderParameters} protectedHeader - The protected header parameters.
   * @returns {this} The current instance for method chaining.
   * @throws {JwsInvalid} If the protected header is already set.
   */
  protectedHeader = (protectedHeader: JwsHeaderParameters): this => {
    if (this.#protectedHeader) {
      throw new JwsInvalid('protectedHeader can only be called once');
    }

    this.#protectedHeader = protectedHeader;

    return this;
  };

  /**
   * Sets the unprotected header for the JWS.
   *
   * @param {JwsHeaderParameters} unprotectedHeader - The unprotected header parameters.
   * @returns {this} The current instance for method chaining.
   * @throws {JwsInvalid} If the unprotected header is already set.
   */
  unprotectedHeader = (unprotectedHeader: JwsHeaderParameters): this => {
    if (this.#unprotectedHeader) {
      throw new JwsInvalid('unprotectedHeader can only be called once');
    }

    this.#unprotectedHeader = unprotectedHeader;

    return this;
  };

  /**
   * Signs the provided payload using the given JWK private key.
   *
   * @param {Uint8Array} payload - The payload to sign.
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key for signing.
   * @param {SignOptions} [options] - Optional signing options.
   * @returns {Promise<FlattenedJws>} A promise that resolves to the signed JWS.
   * @throws {JwsInvalid} If any required parameter is missing or invalid.
   */
  sign = async (
    payload: Uint8Array,
    jwkPrivateKey: JwkPrivateKey,
    options?: SignOptions,
  ): Promise<FlattenedJws> => {
    if (payload == null) {
      throw new JwsInvalid('payload is missing');
    }

    if (!isUint8Array(payload)) {
      throw new JwsInvalid('payload must be a Uint8Array');
    }

    if (jwkPrivateKey == null) {
      throw new JwsInvalid('jwkPrivateKey is missing');
    }

    if (!isPlainObject(jwkPrivateKey)) {
      throw new JwsInvalid('jwkPrivateKey must be a plain object');
    }

    if (!jwkPrivateKey.crv) {
      throw new JwsInvalid('jwkPrivateKey.crv is missing');
    }

    try {
      const signatureCurve = createSignatureCurve(
        jwkPrivateKey.crv,
        this.#randomBytes,
      );
      const privateKey = signatureCurve.toRawPrivateKey(jwkPrivateKey);

      const joseHeader = mergeJwsHeaders({
        protectedHeader: this.#protectedHeader,
        unprotectedHeader: this.#unprotectedHeader,
      });

      const criticalParamNames = validateCrit({
        Err: JweInvalid,
        recognizedDefault: { b64: true },
        recognizedOption: options?.crit,
        protectedHeader: this.#protectedHeader,
        joseHeader,
      });

      const b64 = parseB64(this.#protectedHeader?.b64, criticalParamNames);
      validateJwsAlg(
        this.#protectedHeader?.alg,
        signatureCurve.signatureAlgorithmName,
      );
      const { signTarget, protectedHeaderB64U, payloadB64U } = encodeSignTarget(
        {
          protectedHeader: this.#protectedHeader,
          payload,
          b64,
        },
      );

      const signature = signatureCurve.sign({
        privateKey,
        message: signTarget,
      });

      const jws: FlattenedJws = {
        signature: encodeBase64Url(signature),
        protected: protectedHeaderB64U,
        payload: payloadB64U,
      };

      if (this.#unprotectedHeader) {
        jws.header = this.#unprotectedHeader;
      }

      return jws;
    } catch (error) {
      console.log(getErrorMessage(error));
      throw new JwsInvalid('Failed to sign payload');
    }
  };
}
