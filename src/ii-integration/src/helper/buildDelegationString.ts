import { DelegationChain } from '@dfinity/identity';

/**
 * Builds a delegation string from a DelegationChain.
 *
 * @param {DelegationChain} delegationChain - The delegation chain to convert to a string.
 * @returns {string} The JSON string representation of the delegation.
 */
export const buildDelegationString = (
  delegationChain: DelegationChain,
): string => {
  return JSON.stringify(delegationChain.toJSON());
};
