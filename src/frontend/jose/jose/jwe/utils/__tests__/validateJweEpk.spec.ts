it('should validate EC keys with different supported curves', () => {
  const curves = ['P-256', 'P-384', 'P-521'] as const;
  curves.forEach((crv) => {
    // Generate appropriate key lengths for each curve
    let x: string, y: string;
    switch (crv) {
      case 'P-256':
        x = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 32 bytes base64url encoded
        y = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 32 bytes base64url encoded
        break;
      case 'P-384':
        x =
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 48 bytes base64url encoded
        y =
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 48 bytes base64url encoded
        break;
      case 'P-521':
        x =
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 66 bytes base64url encoded
        y =
          'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'; // 66 bytes base64url encoded
        break;
      default:
        throw new Error(`Unsupported curve: ${crv}`);
    }

    const epk = { ...validEcEpk, crv, x, y };
    const result = validateJweEpk(epk);
    expect(result).toEqual(epk);
  });
});
