/**
 * Array of valid deep link types.
 */
export const DeepLinkTypeArray = Object.freeze([
  'icp',
  'dev-server',
  'expo-go',
  'legacy',
  'modern',
] as const);

/**
 * Type representing a valid deep link type.
 */
export type DeepLinkType = (typeof DeepLinkTypeArray)[number];

/**
 * Checks if a given value is a valid deep link type.
 *
 * @param {string} value - The value to check.
 * @returns {boolean} True if the value is a valid deep link type, false otherwise.
 */
export const isDeepLinkType = (value: string): value is DeepLinkType => {
  return DeepLinkTypeArray.includes(value as DeepLinkType);
};
