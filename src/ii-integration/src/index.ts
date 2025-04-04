import { buildParams } from './helper/buildParams';
import { formatError } from './helper/formatError';
import { renderError } from './helper/renderError';
import { setupLoginButtonHandler } from './helper/setupLoginButtonHandler';
import { prepareButtons } from './helper/prepareButtons';
import { ERROR_MESSAGES } from './constants';
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

    const { iiLoginButton, backToAppButton } = prepareButtons();

    // Set up the login button handler
    await setupLoginButtonHandler({
      iiLoginButton,
      backToAppButton,
      deepLink,
      appPublicKey,
      iiUri,
      window,
    });
  } catch (error) {
    renderError(formatError(ERROR_MESSAGES.INITIALIZATION, error));
  }
};

window.addEventListener('DOMContentLoaded', () => {
  main();
});
