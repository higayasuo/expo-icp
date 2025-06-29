/**
 * Encodes the Additional Authenticated Data (AAD) for AES-based JWE encryption,
 * according to RFC 7516 §5.2: TextEncoder.encode(B64U(protectedHeader) + '.' + B64U(aad))
 */
export const encodeAesAad = (
  protectedHeaderB64U: string,
  aadB64U: string | undefined,
): Uint8Array => {
  const aadString = aadB64U
    ? `${protectedHeaderB64U}.${aadB64U}`
    : protectedHeaderB64U;
  return new TextEncoder().encode(aadString);
};
