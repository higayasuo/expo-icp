/**
 * Signing JSON Web Signature (JWS) in Flattened JSON Serialization
 *
 * @module
 */

import { encodeBase64Url } from 'u8a-utils';
import { areDisjoint } from '@/jose/utils/areDisjoint';
import { JwsInvalid } from '@/jose/errors/errors';
import { validateCrit } from '@/jose/utils/validateCrit';
import { JwkPrivateKey, RandomBytes } from 'noble-curves-extended';
import { FlattenedJws, JwsHeaderParameters, SignOptions } from '../types';

export class FlattenedSigner {
  #randomBytes: RandomBytes;

  #protectedHeader: JwsHeaderParameters | undefined;

  #unprotectedHeader: JwsHeaderParameters | undefined;

  constructor(randomBytes: RandomBytes) {
    this.#randomBytes = randomBytes;
  }

  protectedHeader = (protectedHeader: JwsHeaderParameters): this => {
    if (this.#protectedHeader) {
      throw new JwsInvalid('protectedHeader can only be called once');
    }

    this.#protectedHeader = protectedHeader;

    return this;
  };

  unprotectedHeader = (unprotectedHeader: JwsHeaderParameters): this => {
    if (this.#unprotectedHeader) {
      throw new JwsInvalid('unprotectedHeader can only be called once');
    }

    this.#unprotectedHeader = unprotectedHeader;

    return this;
  };

  sign = async (
    payload: Uint8Array,
    jwkPrivateKey: JwkPrivateKey,
    options?: SignOptions,
  ): Promise<FlattenedJws> => {
    if (!this.#protectedHeader && !this.#unprotectedHeader) {
      throw new JWSInvalid(
        'either setProtectedHeader or setUnprotectedHeader must be called before #sign()',
      );
    }

    if (!isDisjoint(this.#protectedHeader, this.#unprotectedHeader)) {
      throw new JWSInvalid(
        'JWS Protected and JWS Unprotected Header Parameter names must be disjoint',
      );
    }

    const joseHeader: types.JWSHeaderParameters = {
      ...this.#protectedHeader,
      ...this.#unprotectedHeader,
    };

    const extensions = validateCrit(
      JWSInvalid,
      new Map([['b64', true]]),
      options?.crit,
      this.#protectedHeader,
      joseHeader,
    );

    let b64 = true;
    if (extensions.has('b64')) {
      b64 = this.#protectedHeader.b64!;
      if (typeof b64 !== 'boolean') {
        throw new JWSInvalid(
          'The "b64" (base64url-encode payload) Header Parameter must be a boolean',
        );
      }
    }

    const { alg } = joseHeader;

    if (typeof alg !== 'string' || !alg) {
      throw new JWSInvalid(
        'JWS "alg" (Algorithm) Header Parameter missing or invalid',
      );
    }

    checkKeyType(alg, key, 'sign');

    //let payload = this.#payload;
    if (b64) {
      payload = encoder.encode(b64u(payload));
    }

    let protectedHeader: Uint8Array;
    if (this.#protectedHeader) {
      protectedHeader = encoder.encode(
        b64u(JSON.stringify(this.#protectedHeader)),
      );
    } else {
      protectedHeader = encoder.encode('');
    }

    const data = concat(protectedHeader, encoder.encode('.'), payload);

    const k = await normalizeKey(key, alg);
    const signature = await sign(alg, k, data);

    const jws: types.FlattenedJWS = {
      signature: b64u(signature),
      payload: '',
    };

    if (b64) {
      jws.payload = decoder.decode(payload);
    }

    if (this.#unprotectedHeader) {
      jws.header = this.#unprotectedHeader;
    }

    if (this.#protectedHeader) {
      jws.protected = decoder.decode(protectedHeader);
    }

    return jws;
  };
}
