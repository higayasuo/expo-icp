import { describe, it, expect, vi } from 'vitest';
import { generateMitigatedCek } from '../generateMitigatedCek';
import { createEcdhCurve } from 'noble-curves-extended';
import { webCryptoModule } from 'expo-crypto-universal-web';

const { getRandomBytes } = webCryptoModule;
const curve = createEcdhCurve('P-256', getRandomBytes);

describe('generateMitigatedCek', () => {
  it('should generate CEK with correct length for each encryption algorithm', async () => {
    const testCases = [
      { enc: 'A256GCM', expectedLength: 32 }, // 256 bits = 32 bytes
      { enc: 'A192GCM', expectedLength: 24 }, // 192 bits = 24 bytes
      { enc: 'A128GCM', expectedLength: 16 }, // 128 bits = 16 bytes
      { enc: 'A256CBC-HS512', expectedLength: 64 }, // 512 bits = 64 bytes
      { enc: 'A192CBC-HS384', expectedLength: 48 }, // 384 bits = 48 bytes
      { enc: 'A128CBC-HS256', expectedLength: 32 }, // 256 bits = 32 bytes
    ] as const;

    for (const { enc, expectedLength } of testCases) {
      const cek = await generateMitigatedCek(curve, enc);
      expect(cek).toBeInstanceOf(Uint8Array);
      expect(cek.length).toBe(expectedLength);
    }
  });

  it('should add random delay between 200ms and 500ms', async () => {
    const sleepSpy = vi.spyOn(global, 'setTimeout');
    const startTime = Date.now();

    await generateMitigatedCek(curve, 'A256GCM');

    const endTime = Date.now();
    const delay = endTime - startTime;

    expect(sleepSpy).toHaveBeenCalled();
    expect(delay).toBeGreaterThanOrEqual(200);
    expect(delay).toBeLessThanOrEqual(500);
  });

  it('should generate different CEKs for each call', async () => {
    const cek1 = await generateMitigatedCek(curve, 'A256GCM');
    const cek2 = await generateMitigatedCek(curve, 'A256GCM');
    expect(cek1).not.toEqual(cek2);
  });
});
