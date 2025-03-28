/**
 * Builds a delegation string from a DelegationIdentity.
 *
 * @param {DelegationIdentity} delegationIdentity - The delegation identity to convert to a string.
 * @returns {string} The JSON string representation of the delegation.
 */
export const buildDelegationString = (delegationIdentity) => {
    return JSON.stringify(delegationIdentity.getDelegation().toJSON());
};
