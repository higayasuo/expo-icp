import { DelegationChain } from '@dfinity/identity';
import { buildDelegationString } from './buildDelegationString';

/**
 * Sends delegation information to the parent window using postMessage.
 *
 * @param {Object} params - The parameters for sending delegation
 * @param {string} params.deepLink - The deep link to redirect to after processing the delegation
 * @param {DelegationChain} params.delegationChain - The delegation chain to send
 * @param {Window & typeof globalThis} params.window - The window object from the web environment
 */
export const sendDelegationToParent = ({
  deepLink,
  delegationChain,
  window,
}: {
  deepLink: string;
  delegationChain: DelegationChain;
  window: Window & typeof globalThis;
}): void => {
  console.log('Web browser detected, using postMessage');
  const message = {
    kind: 'success',
    delegation: buildDelegationString(delegationChain),
  };
  window.parent.postMessage(message, new URL(deepLink).origin);
};
