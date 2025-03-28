import { CanisterManager } from 'canister-manager';

import {
  LOCAL_IP_ADDRESS,
  DFX_NETWORK,
  CANISTER_ID_FRONTEND,
} from '../env.generated';

/**
 * Builds the redirect URI based on the provided environment.
 *
 * @param {string} environment - The environment for which to build the redirect URI.
 * @returns {string} The built redirect URI.
 * @throws Will throw an error if the environment is not supported.
 */
export const buildRedirectUri = (environment: string): string => {
  if (environment === 'storeClient') {
    return `exp://${LOCAL_IP_ADDRESS}:8081/--/`;
  } else if (environment === 'bare') {
    return 'http://localhost:8081';
  } else if (environment === 'icp') {
    const canisterManager = new CanisterManager({
      localIPAddress: LOCAL_IP_ADDRESS,
      dfxNetwork: DFX_NETWORK,
    });
    return canisterManager.getFrontendCanisterURL(CANISTER_ID_FRONTEND);
  } else {
    throw new Error(`Not supported environment: ${environment}`);
  }
};
