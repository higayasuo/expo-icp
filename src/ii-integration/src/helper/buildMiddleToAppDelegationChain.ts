import { PublicKey } from '@dfinity/agent';
import { DelegationChain, DelegationIdentity } from '@dfinity/identity';

/**
 * Parameters required for building the middle to app delegation chain.
 */
type BuildMiddleToAppDelegationChainParams = {
  /** The middle delegation identity containing the delegation information. */
  middleDelegationIdentity: DelegationIdentity;
  /** The application public key. */
  appPublicKey: PublicKey;
  /** The expiration time of the delegation. */
  expiration: Date;
};

/**
 * Builds a delegation chain from the middle delegation identity to the application public key.
 *
 * @param {BuildMiddleToAppDelegationChainParams} params - The parameters containing the middle delegation identity and application public key.
 * @returns {Promise<DelegationChain>} A promise that resolves to the created delegation chain.
 */
export const buildMiddleToAppDelegationChain = ({
  middleDelegationIdentity,
  appPublicKey,
  expiration,
}: BuildMiddleToAppDelegationChainParams): Promise<DelegationChain> => {
  return DelegationChain.create(
    middleDelegationIdentity,
    appPublicKey,
    expiration,
    {
      previous: middleDelegationIdentity.getDelegation(),
    },
  );
};
