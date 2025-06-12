import { describe, it, expect } from 'vitest';
import { sleep } from '../sleep';

describe('sleep', () => {
  it('should wait for the specified duration', async () => {
    const start = Date.now();
    const delay = 100;

    await sleep(delay);

    const end = Date.now();
    const elapsed = end - start;

    // Allow for a small margin of error (±10ms) due to system scheduling
    expect(elapsed).toBeGreaterThanOrEqual(delay - 10);
    expect(elapsed).toBeLessThanOrEqual(delay + 10);
  });

  it('should handle zero delay', async () => {
    const start = Date.now();
    await sleep(0);
    const end = Date.now();
    const elapsed = end - start;

    // Zero delay should be very quick, but not necessarily exactly 0ms
    expect(elapsed).toBeLessThan(10);
  });

  it('should handle multiple consecutive calls', async () => {
    const delays = [50, 100, 150];
    const start = Date.now();

    for (const delay of delays) {
      await sleep(delay);
    }

    const end = Date.now();
    const elapsed = end - start;
    const totalDelay = delays.reduce((sum, delay) => sum + delay, 0);

    // Allow for a small margin of error (±20ms) due to system scheduling
    expect(elapsed).toBeGreaterThanOrEqual(totalDelay - 20);
    expect(elapsed).toBeLessThanOrEqual(totalDelay + 20);
  });
});
