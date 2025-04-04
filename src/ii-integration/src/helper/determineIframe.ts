/**
 * Determines if the current window is an iframe.
 *
 * @param {Window & typeof globalThis} window - The window object from the web environment.
 * @returns {boolean} True if the current window is an iframe, false otherwise.
 */
export const determineIframe = (
  window: Window & typeof globalThis,
): boolean => {
  return window.parent !== undefined && window.parent !== window;
};
