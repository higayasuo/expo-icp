import { PublicKey } from '@dfinity/agent';
import { DelegationChain, DelegationIdentity } from '@dfinity/identity';
import { buildDelegationString } from './buildDelegationString';
import { buildURIFragment } from './buildURIFragment';
import { buildMiddleToAppDelegationChain } from './buildMiddleToAppDelegationChain';

/**
 * Parameters required for processing delegation.
 */
type ProcessDelegationParams = {
  /** The deep link to redirect to after processing the delegation */
  deepLink: string;
  /**
   * The middle delegation identity containing the delegation information.
   */
  middleDelegationIdentity: DelegationIdentity;
  /** The application public key */
  appPublicKey: PublicKey;
  /** The expiration time of the delegation */
  expiration: Date;
};

export const processDelegation = async ({
  deepLink,
  middleDelegationIdentity,
  appPublicKey,
  expiration,
}: ProcessDelegationParams): Promise<void> => {
  // Check if we're in an iframe (web browser case)
  const isIframe = window.parent !== undefined && window.parent !== window;
  const delegationChain = await buildMiddleToAppDelegationChain({
    middleDelegationIdentity,
    appPublicKey,
    expiration,
  });

  if (isIframe) {
    // We're in a web browser iframe
    console.log('Web browser detected, using postMessage');
    const message = {
      kind: 'success',
      delegation: buildDelegationString(delegationChain),
    };
    window.parent.postMessage(message, new URL(deepLink).origin);
  } else {
    // We're in a native app's WebView
    console.log('Native app detected, using URL redirection');
    const uriFragment = buildURIFragment(delegationChain);
    window.location.assign(`${deepLink}#${uriFragment}`);
  }
};
