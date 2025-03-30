import { buildParams } from './helper/buildParams';
import { formatError } from './helper/formatError';
import { prepareLogin } from './helper/prepareLogin';
import { renderError } from './helper/renderError';
import { ERROR_MESSAGES, LOGIN_BUTTON_SELECTOR } from './constants';

const main = async (): Promise<void> => {
  try {
    const { redirectUri, appPublicKey, iiUri } = buildParams();
    console.log('redirectUri', redirectUri);
    console.log('iiUri', iiUri);

    const login = await prepareLogin({
      redirectUri,
      appPublicKey,
      iiUri,
    });

    const loginButton = document.querySelector(
      LOGIN_BUTTON_SELECTOR,
    ) as HTMLButtonElement;

    if (!loginButton) {
      throw new Error('Login button not found');
    }

    loginButton.addEventListener('click', async (e) => {
      e.preventDefault();
      renderError('');
      try {
        await login();
      } catch (error) {
        renderError(formatError(ERROR_MESSAGES.LOGIN_PROCESS, error));
      }
    });
  } catch (error) {
    renderError(formatError(ERROR_MESSAGES.INITIALIZATION, error));
  }
};

window.addEventListener('DOMContentLoaded', () => {
  main();
});
