import { buildParams } from './helper/buildParams';
import { formatError } from './helper/formatError';
import { prepareLogin } from './helper/prepareLogin';
import { renderError } from './helper/renderError';
import { ERROR_MESSAGES, LOGIN_BUTTON_SELECTOR } from './constants';
import {
  LOCAL_IP_ADDRESS,
  DFX_NETWORK,
  CANISTER_ID_INTERNET_IDENTITY,
  CANISTER_ID_FRONTEND,
  EXPO_SCHEME,
} from './env.generated';

const main = async (): Promise<void> => {
  try {
    const { deepLink, appPublicKey, iiUri } = buildParams({
      localIPAddress: LOCAL_IP_ADDRESS,
      dfxNetwork: DFX_NETWORK,
      internetIdentityCanisterId: CANISTER_ID_INTERNET_IDENTITY,
      frontendCanisterId: CANISTER_ID_FRONTEND,
      expoScheme: EXPO_SCHEME,
    });
    console.log('deepLink', deepLink);
    console.log('iiUri', iiUri);

    const login = await prepareLogin({
      deepLink,
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
