import { RandomBytes, JwkPublicKey } from 'noble-curves-extended';
import {
  CompactJwsHeaderParameters,
  CompactVerifyResult,
} from '@/jose/jws/compact/types';
import { FlattenedVerifier } from '@/jose/jws/flattened/FlattenedVerifier';
import { VerifyOptions } from '@/jose/jws/types';
import { JwsInvalid } from '@/jose/errors';

/**
 * Class representing a Compact JWS Verifier.
 */
export class CompactVerifier {
  #flattened: FlattenedVerifier;

  /**
   * Creates an instance of CompactVerifier.
   * @param {RandomBytes} randomBytes - An instance of RandomBytes for cryptographic operations.
   */
  constructor(randomBytes: RandomBytes) {
    this.#flattened = new FlattenedVerifier(randomBytes);
  }

  /**
   * Verifies a Compact JWS signature.
   *
   * @param jws - The Compact JWS string in format "header.payload.signature"
   * @param jwkPublicKey - The JWK public key for signature verification
   * @param options - Optional verification options
   * @returns Promise that resolves to verification result with payload and headers
   * @throws {JwsInvalid} When JWS format is invalid
   * @throws {JwsSignatureVerificationFailed} When signature verification fails
   */
  verify = async (
    jws: string,
    jwkPublicKey: JwkPublicKey,
    options?: VerifyOptions,
  ): Promise<CompactVerifyResult> => {
    if (jws == null) {
      throw new JwsInvalid('Compact JWS is missing');
    }

    if (typeof jws !== 'string') {
      throw new JwsInvalid('Compact JWS must be a string');
    }

    if (jws.trim() === '') {
      throw new JwsInvalid('Compact JWS cannot be empty');
    }

    const {
      0: protectedHeader,
      1: payload,
      2: signature,
      length,
    } = jws.split('.');

    if (length !== 3) {
      throw new JwsInvalid('Compact JWS must have 3 parts');
    }

    const verified = await this.#flattened.verify(
      { payload, protected: protectedHeader, signature },
      jwkPublicKey,
      options,
    );

    const result = {
      payload: verified.payload,
      protectedHeader: verified.protectedHeader as CompactJwsHeaderParameters,
    };

    return result;
  };
}
