import { DelegationIdentity, ECDSAKeyIdentity } from '@dfinity/identity';
import { AuthClient } from '@dfinity/auth-client';

import { BuildParamsResult } from './buildParams';
import { processDelegation } from './processDelegation';

type PrepareLoginArgs = BuildParamsResult & {
  expiration?: Date;
};

export const prepareLogin = async ({
  appPublicKey,
  iiUri,
  redirectUri,
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
          redirectUri,
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
