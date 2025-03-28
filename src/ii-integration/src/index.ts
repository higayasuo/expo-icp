import { AuthClient } from '@dfinity/auth-client';
import { DelegationIdentity } from '@dfinity/identity';
import { buildParams } from './helper/buildParams';
import { formatError } from './helper/formatError';
import { processDelegation } from './helper/processDelegation';
import { renderError } from './helper/renderError';
import { ERROR_MESSAGES, LOGIN_BUTTON_SELECTOR } from './constants';
const main = async (): Promise<void> => {
  try {
    const { redirectUri, identity, iiUri } = buildParams();
    console.log('redirectUri', redirectUri);
    console.log('iiUri', iiUri);

    const authClient = await AuthClient.create({ identity });
    const loginButton = document.querySelector(
      LOGIN_BUTTON_SELECTOR,
    ) as HTMLButtonElement;

    if (!loginButton) {
      throw new Error('Login button not found');
    }

    loginButton.addEventListener('click', async () => {
      renderError('');
      try {
        await authClient.login({
          identityProvider: iiUri,
          onSuccess: () => {
            try {
              const delegationIdentity =
                authClient.getIdentity() as DelegationIdentity;

              processDelegation({
                redirectUri,
                delegationIdentity,
              });
            } catch (error) {
              renderError(
                formatError(ERROR_MESSAGES.DELEGATION_PROCESS, error),
              );
            }
          },
          onError: (error?: string) => {
            renderError(
              formatError(
                ERROR_MESSAGES.AUTHENTICATION_REJECTED,
                error || 'Unknown error',
              ),
            );
          },
        });
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
