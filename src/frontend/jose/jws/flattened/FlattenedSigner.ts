/**
 * Signing JSON Web Signature (JWS) in Flattened JSON Serialization
 *
 * @module
 */

import { encodeBase64Url, isUint8Array } from 'u8a-utils';
import { areDisjoint } from '@/jose/utils/areDisjoint';
import { JweInvalid, JwsInvalid } from '@/jose/errors/errors';
import { validateCrit } from '@/jose/utils/validateCrit';
import { JwkPrivateKey, RandomBytes } from 'noble-curves-extended';
import { FlattenedJws, JwsHeaderParameters, SignOptions } from '../types';
import { isPlainObject } from '@/jose/utils/isPlainObject';
import { mergeJwsHeaders } from './utils/mergeJwsHeader';

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
    if (!payload) {
      throw new JwsInvalid('payload is missing');
    }

    if (!isUint8Array(payload)) {
      throw new JwsInvalid('payload must be a Uint8Array');
    }

    if (!jwkPrivateKey) {
      throw new JwsInvalid('jwkPrivateKey is missing');
    }

    if (!isPlainObject(jwkPrivateKey)) {
      throw new JwsInvalid('jwkPrivateKey must be a plain object');
    }

    if (!jwkPrivateKey.crv) {
      throw new JwsInvalid('jwkPrivateKey.crv is missing');
    }

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

    // const criticalParamNames = validateCrit(
    //   JwsInvalid,
    //   new Map([['b64', true]]),
    //   options?.crit,
    //   this.#protectedHeader,
    //   joseHeader,
    // );

    let b64 = true;
    if (criticalParamNames.has('b64')) {
      b64 = this.#protectedHeader.b64!;
      if (typeof b64 !== 'boolean') {
        throw new JwsInvalid(
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
