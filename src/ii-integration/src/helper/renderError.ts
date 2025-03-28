/**
 * Renders an error message in the designated error element.
 *
 * @param {string} message - The error message to display.
 * @returns {void}
 */
export const renderError = (message: string): void => {
  const errorElement = document.querySelector('#error') as HTMLParagraphElement;
  if (!errorElement) {
    console.error('Error element not found');
    return;
  }

  errorElement.textContent = message;
  errorElement.style.display = message ? 'block' : 'none';
};
