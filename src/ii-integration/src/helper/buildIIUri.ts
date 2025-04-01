import { CanisterManager } from 'canister-manager';

/**
 * Arguments required to build the Internet Identity URI.
 */
type BuildIIUriArgs = {
  /**
   * The local IP address.
   */
  localIPAddress: string;

  /**
   * The DFX network.
   */
  dfxNetwork: string;

  /**
   * The canister ID for Internet Identity.
   */
  internetIdentityCanisterId: string;
};

/**
 * Builds the Internet Identity URI using the CanisterManager.
 *
 * @param {BuildIIUriArgs} args - Configuration object containing necessary parameters.
 * @returns {string} The Internet Identity URI.
 */
export const buildIIUri = ({
  localIPAddress,
  dfxNetwork,
  internetIdentityCanisterId,
}: BuildIIUriArgs): string => {
  const canisterManager = new CanisterManager({
    localIPAddress,
    dfxNetwork,
  });

  return canisterManager.getInternetIdentityURL(internetIdentityCanisterId);
};
