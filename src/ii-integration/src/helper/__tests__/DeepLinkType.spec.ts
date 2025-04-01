import { describe, it, expect } from 'vitest';
import {
  DeepLinkType,
  DeepLinkTypeArray,
  isDeepLinkType,
} from '../DeepLinkType';

describe('DeepLinkType', () => {
  describe('isDeepLinkType', () => {
    it('should return true for valid deep link type values', () => {
      DeepLinkTypeArray.forEach((type) => {
        expect(isDeepLinkType(type)).toBe(true);
      });
    });

    it('should return false for invalid deep link type values', () => {
      const invalidTypes = [
        '',
        'invalid',
        'ICP',
        'DEV_SERVER',
        'unknown',
        'web',
        'android',
      ];

      invalidTypes.forEach((invalidType) => {
        expect(isDeepLinkType(invalidType)).toBe(false);
      });
    });
  });

  describe('DeepLinkTypeArray', () => {
    it('should contain all expected deep link type values', () => {
      const expectedTypes = [
        'icp',
        'dev-server',
        'expo-go',
        'legacy',
        'modern',
      ];

      expect(DeepLinkTypeArray).toEqual(expectedTypes);
    });

    it('should be readonly array', () => {
      expect(Object.isFrozen(DeepLinkTypeArray)).toBe(true);
    });
  });

  // Type test (this is more for documentation, as it's checked at compile time)
  it('type test - should allow valid deep link type values', () => {
    const type: DeepLinkType = 'icp';
    expect(isDeepLinkType(type)).toBe(true);
  });
});
