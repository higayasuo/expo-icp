import { CanisterManager } from 'canister-manager';
import {
  LOCAL_IP_ADDRESS,
  DFX_NETWORK,
  CANISTER_ID_INTERNET_IDENTITY,
} from '../env.generated';

/**
 * Builds the Internet Identity URI using the CanisterManager.
 *
 * @returns {string} The Internet Identity URI.
 */
export const buildIIUri = (): string => {
  const canisterManager = new CanisterManager({
    localIPAddress: LOCAL_IP_ADDRESS,
    dfxNetwork: DFX_NETWORK,
  });

  return canisterManager.getInternetIdentityURL(CANISTER_ID_INTERNET_IDENTITY);
};
