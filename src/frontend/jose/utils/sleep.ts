/**
 * Creates a promise that resolves after a specified delay.
 *
 * @param ms - The delay in milliseconds.
 * @returns A promise that resolves after the specified delay.
 */
export const sleep = (ms: number): Promise<void> =>
  new Promise((resolve) => setTimeout(resolve, ms));
