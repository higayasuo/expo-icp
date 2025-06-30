import { FlattenedSigner } from '@/jose/jws/flattened/FlattenedSigner';
import { RandomBytes, JwkPrivateKey } from 'noble-curves-extended';
import { CompactJwsHeaderParameters } from '@/jose/jws/compact/types';
import { JwsHeaderParameters, SignOptions } from '@/jose/jws/types';
import { parseBase64UrlHeader } from '@/jose/utils/parseBase64UrlHeader';
import { JwsInvalid } from '@/jose/errors';

/**
 * Class representing a Compact JWS Signer.
 */
export class CompactSigner {
  #flattened: FlattenedSigner;

  /**
   * Creates an instance of CompactSigner.
   * @param {RandomBytes} randomBytes - An instance of RandomBytes for cryptographic operations.
   */
  constructor(randomBytes: RandomBytes) {
    this.#flattened = new FlattenedSigner(randomBytes);
  }

  /**
   * Sets the protected header for the JWS.
   * @param {CompactJwsHeaderParameters} protectedHeader - The protected header parameters.
   * @returns {this} The current instance for method chaining.
   */
  protectedHeader = (protectedHeader: CompactJwsHeaderParameters): this => {
    this.#flattened.protectedHeader(protectedHeader);
    return this;
  };

  /**
   * Signs the payload using the provided JWK private key and options.
   * @param {Uint8Array} payload - The payload to be signed.
   * @param {JwkPrivateKey} jwkPrivateKey - The JWK private key for signing.
   * @param {SignOptions} [options] - Optional signing options.
   * @returns {Promise<string>} A promise that resolves to the compact JWS string.
   * @throws {TypeError} Throws if the JWS payload is undefined.
   */
  sign = async (
    payload: Uint8Array,
    jwkPrivateKey: JwkPrivateKey,
    options?: SignOptions,
  ): Promise<string> => {
    const jws = await this.#flattened.sign(payload, jwkPrivateKey, options);
    const parsedProtected = parseBase64UrlHeader<JwsHeaderParameters>(
      jws.protected,
      'JWS Protected Header',
    );

    if (!jws.payload && parsedProtected.b64 === false) {
      throw new JwsInvalid(
        'use the flattened module for creating JWS with b64: false',
      );
    }

    return `${jws.protected}.${jws.payload}.${jws.signature}`;
  };
}
