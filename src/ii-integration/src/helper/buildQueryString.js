import { buildDelegationString } from './buildDelegationString';
/**
 * Builds a query string containing the encoded delegation information.
 *
 * @param {DelegationIdentity} delegationIdentity - The delegation identity containing the delegation information.
 * @returns {string} A query string in the format 'delegation=<encoded_delegation_string>'.
 */
export const buildQueryString = (delegationIdentity) => {
    const delegationString = buildDelegationString(delegationIdentity);
    const encodedDelegation = encodeURIComponent(delegationString);
    return `delegation=${encodedDelegation}`;
};
