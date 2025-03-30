import { DelegationIdentity } from '@dfinity/identity';
import { buildDelegationString } from './buildDelegationString';

/**
 * Builds a URI fragment containing the encoded delegation information.
 * This is used for secure transmission of delegation data in the URL fragment
 * (the part after #) which is not sent to the server.
 *
 * @param {DelegationIdentity} delegationIdentity - The delegation identity containing the delegation information.
 * @returns {string} A URI fragment in the format 'delegation=<encoded_delegation_string>'.
 */
export const buildURIFragment = (
  delegationIdentity: DelegationIdentity,
): string => {
  const delegationString = buildDelegationString(delegationIdentity);
  const encodedDelegation = encodeURIComponent(delegationString);
  return `delegation=${encodedDelegation}`;
};
