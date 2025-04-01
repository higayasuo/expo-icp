import { PublicKey } from '@dfinity/agent';
import { buildAppPublicKey } from './buildAppPublicKey';
import { buildIIUri } from './buildIIUri';
import { buildDeepLink } from './buildDeepLink';
import { DeepLinkType, isDeepLinkType } from './DeepLinkType';

/**
 * Arguments required to build the parameters for the application.
 */
type BuildParamsArgs = {
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

  /**
   * The canister ID for the frontend.
   */
  frontendCanisterId: string;

  /**
   * The Expo scheme.
   */
  expoScheme: string;
};

/**
 * Interface representing the result of the buildParams function.
 */
export interface BuildParamsResult {
  appPublicKey: PublicKey;
  iiUri: string;
  deepLink: string;
}

/**
 * Builds the parameters required for the application.
 *
 * @param {BuildParamsArgs} args - Configuration object containing necessary parameters.
 * @returns {BuildParamsResult} The built parameters including identity, iiUri, and deepLink.
 * @throws Will throw an error if pubkey or deep-link-type is missing in query string or if deep-link-type is not a valid DeepLinkType.
 */
export const buildParams = ({
  localIPAddress,
  dfxNetwork,
  internetIdentityCanisterId,
  frontendCanisterId,
  expoScheme,
}: BuildParamsArgs): BuildParamsResult => {
  const searchParams = new URLSearchParams(window.location.search);
  const pubkey = searchParams.get('pubkey');
  const deepLinkType = searchParams.get('deep-link-type') as DeepLinkType;

  if (!pubkey || !deepLinkType) {
    throw new Error('Missing pubkey or deep-link-type in query string');
  }

  if (!isDeepLinkType(deepLinkType)) {
    throw new Error(`Invalid deep-link-type: ${deepLinkType}`);
  }

  const appPublicKey = buildAppPublicKey(pubkey);
  const iiUri = buildIIUri({
    localIPAddress,
    dfxNetwork,
    internetIdentityCanisterId,
  });
  const deepLink = buildDeepLink({
    deepLinkType,
    localIPAddress,
    dfxNetwork,
    frontendCanisterId,
    expoScheme,
  });

  return { appPublicKey, iiUri, deepLink };
};
