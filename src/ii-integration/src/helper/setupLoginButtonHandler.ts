import { PublicKey } from '@dfinity/agent';
import { prepareLogin } from './prepareLogin';
import { buildMiddleToAppDelegationChain } from './buildMiddleToAppDelegationChain';
import { determineIframe } from './determineIframe';
import { sendDelegationToParent } from './sendDelegationToParent';
import { handleNativeAppDelegation } from './handleNativeAppDelegation';
import { renderError } from './renderError';
import { formatError } from './formatError';
import { ERROR_MESSAGES } from './constants';

/**
 * Parameters for setting up the login button handler
 */
type SetupLoginButtonHandlerParams = {
  /** The Internet Identity login button element */
  iiLoginButton: HTMLButtonElement;
  /** The back to app button element */
  backToAppButton: HTMLButtonElement;
  /** The deep link URL for the app */
  deepLink: string;
  /** The public key for the app */
  appPublicKey: PublicKey;
  /** The Internet Identity URI */
  iiUri: string;
  /** The window object to use for iframe detection and delegation */
  window: Window & typeof globalThis;
};

/**
 * Sets up the click event handler for the Internet Identity login button
 * @param params - The parameters for setting up the login button handler
 */
export const setupLoginButtonHandler = async (
  params: SetupLoginButtonHandlerParams,
): Promise<void> => {
  const {
    iiLoginButton,
    backToAppButton,
    deepLink,
    appPublicKey,
    iiUri,
    window,
  } = params;

  // Prepare login outside of the event handler
  const login = await prepareLogin({
    iiUri,
  });

  iiLoginButton.addEventListener('click', async (e) => {
    e.preventDefault();
    renderError('');
    try {
      const middleDelegationIdentity = await login();
      const expiration = new Date(Date.now() + 1000 * 60 * 15); // 15 minutes from now

      // Build the delegation chain
      const delegationChain = await buildMiddleToAppDelegationChain({
        middleDelegationIdentity,
        appPublicKey,
        expiration,
      });

      // Check if we're in an iframe (web browser case)
      const isIframe = determineIframe(window);

      if (isIframe) {
        // We're in a web browser iframe
        sendDelegationToParent({
          deepLink,
          delegationChain,
          window,
        });
      } else {
        // We're in a native app's WebView
        handleNativeAppDelegation({
          deepLink,
          delegationChain,
          window,
          iiLoginButton,
          backToAppButton,
        });
      }
    } catch (error) {
      renderError(formatError(ERROR_MESSAGES.LOGIN_PROCESS, error));
    }
  });
};
