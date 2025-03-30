import { DelegationIdentity } from '@dfinity/identity';
import { buildDelegationString } from './buildDelegationString';
import { buildURIFragment } from './buildURIFragment';

/**
 * Parameters required for processing delegation.
 */
type ProcessDelegationParams = {
  /** The URI to redirect to after processing the delegation */
  redirectUri: string;
  /** The delegation identity containing the delegation information */
  delegationIdentity: DelegationIdentity;
};

/**
 * Processes the delegation based on the environment (web browser or native app).
 *
 * For web browsers (iframe):
 * - Sends a postMessage to the parent window with the delegation information
 *
 * For native apps (WebView):
 * - Redirects to the redirectUri with the delegation information as a URL fragment
 *
 * @param {ProcessDelegationParams} params - The parameters containing the redirect URI and delegation identity
 */
export const processDelegation = ({
  redirectUri,
  delegationIdentity,
}: ProcessDelegationParams) => {
  // Check if we're in an iframe (web browser case)
  const isIframe = window.parent !== window;

  if (isIframe) {
    // We're in a web browser iframe
    console.log('Web browser detected, using postMessage');
    const message = {
      kind: 'success',
      delegation: buildDelegationString(delegationIdentity),
    };
    window.parent.postMessage(message, new URL(redirectUri).origin);
  } else {
    // We're in a native app's WebView
    console.log('Native app detected, using URL redirection');
    const uriFragment = buildURIFragment(delegationIdentity);
    window.location.href = `${redirectUri}#${uriFragment}`;
  }
};
