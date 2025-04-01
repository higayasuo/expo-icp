import { DelegationIdentity, ECDSAKeyIdentity } from '@dfinity/identity';
import { AuthClient } from '@dfinity/auth-client';

import { BuildParamsResult } from './buildParams';
import { processDelegation } from './processDelegation';

/**
 * Arguments required for preparing the login process.
 *
 * @typedef {Object} PrepareLoginArgs
 * @property {PublicKey} appPublicKey - The public key of the application.
 * @property {string} iiUri - The Internet Identity URI.
 * @property {string} frontendUri - The frontend URI after login.
 * @property {Date} [expiration] - Optional expiration date for the delegation.
 */
type PrepareLoginArgs = BuildParamsResult & {
  expiration?: Date;
};

/**
 * Prepares the login process by creating an identity and an authentication client.
 * Returns a function that initiates the login process when called.
 *
 * @param {PrepareLoginArgs} args - The arguments required to prepare the login.
 * @returns {Promise<() => Promise<void>>} A promise that resolves to a function which handles the login process.
 */
export const prepareLogin = async ({
  appPublicKey,
  iiUri,
  deepLink,
  expiration = new Date(Date.now() + 1000 * 60 * 15),
}: PrepareLoginArgs): Promise<() => Promise<void>> => {
  const identity = await ECDSAKeyIdentity.generate();
  const authClient = await AuthClient.create({ identity });

  return async () => {
    await authClient.login({
      identityProvider: iiUri,
      onSuccess: () => {
        const middleDelegationIdentity =
          authClient.getIdentity() as DelegationIdentity;

        processDelegation({
          deepLink,
          middleDelegationIdentity,
          appPublicKey,
          expiration,
        });
      },
      onError: (error?: string) => {
        throw new Error(error || 'Unknown error');
      },
    });
  };
};
