/**
 * Renders an error message in the designated error element.
 *
 * @param {string} message - The error message to display.
 * @returns {void}
 */
export const renderError = (message) => {
    const errorElement = document.querySelector('#error');
    if (!errorElement) {
        console.error('Error element not found');
        return;
    }
    errorElement.textContent = message;
    errorElement.style.display = message ? 'block' : 'none';
};
