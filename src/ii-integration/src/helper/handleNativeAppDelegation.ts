import { DelegationChain } from '@dfinity/identity';
import { buildURIFragment } from './buildURIFragment';

/**
 * Handles delegation in a native app environment by setting up UI elements and redirecting.
 *
 * @param {Object} params - The parameters for handling native app delegation
 * @param {string} params.deepLink - The deep link to redirect to after processing the delegation
 * @param {DelegationChain} params.delegationChain - The delegation chain to use
 * @param {Window & typeof globalThis} params.window - The window object from the web environment
 * @param {HTMLElement} params.iiLoginButton - The II login button element
 * @param {HTMLElement} params.backToAppButton - The back to app button element
 */
export const handleNativeAppDelegation = ({
  deepLink,
  delegationChain,
  window,
  iiLoginButton,
  backToAppButton,
}: {
  deepLink: string;
  delegationChain: DelegationChain;
  window: Window & typeof globalThis;
  iiLoginButton: HTMLElement;
  backToAppButton: HTMLElement;
}): void => {
  console.log('Native app detected, using URL redirection');
  const uriFragment = buildURIFragment(delegationChain);

  // Hide the II login button and show the Back to App button
  iiLoginButton.style.display = 'none';
  backToAppButton.style.display = 'block';

  // Add click event listener to the Back to App button
  backToAppButton.addEventListener('click', () => {
    window.open(`${deepLink}#${uriFragment}`, '_self');
  });
};
