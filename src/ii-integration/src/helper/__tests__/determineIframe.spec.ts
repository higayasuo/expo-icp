import { describe, it, expect } from 'vitest';
import { determineIframe } from '../determineIframe';

describe('determineIframe', () => {
  it('should return true when window is in an iframe', () => {
    // Mock window object for iframe environment
    const mockParent = { someProperty: 'value' };
    const mockWindow = {
      parent: mockParent,
    } as unknown as Window & typeof globalThis;

    const result = determineIframe(mockWindow);
    expect(result).toBe(true);
  });

  it('should return false when window is not in an iframe', () => {
    // Mock window object for non-iframe environment
    const mockWindow = {
      parent: undefined,
    } as unknown as Window & typeof globalThis;

    const result = determineIframe(mockWindow);
    expect(result).toBe(false);
  });

  it('should return false when window.parent is the same as window', () => {
    // Mock window object where parent is the same as window
    const mockWindow = {
      parent: {} as Window & typeof globalThis,
    } as unknown as Window & typeof globalThis;

    // Set parent to be the same as window
    mockWindow.parent = mockWindow;

    const result = determineIframe(mockWindow);
    expect(result).toBe(false);
  });
});
