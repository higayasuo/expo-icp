import { CanisterManager } from 'canister-manager';

import { DeepLinkType } from './DeepLinkType';

type BuildDeepLinkArgs = {
  deepLinkType: DeepLinkType;
  localIPAddress: string;
  dfxNetwork: string;
  frontendCanisterId: string;
  expoScheme: string;
};

export const buildDeepLink = ({
  deepLinkType,
  localIPAddress,
  dfxNetwork,
  frontendCanisterId,
  expoScheme,
}: BuildDeepLinkArgs): string => {
  const canisterManager = new CanisterManager({
    localIPAddress,
    dfxNetwork,
  });
  const frontendCanisterURL =
    canisterManager.getFrontendCanisterURL(frontendCanisterId);

  switch (deepLinkType) {
    case 'icp':
      return frontendCanisterURL;
    case 'dev-server':
      return 'http://localhost:8081/';
    case 'expo-go':
      return `exp://${localIPAddress}:8081/--/`;
    case 'legacy':
      return `${expoScheme}://`;
    case 'modern':
      if (frontendCanisterURL.startsWith('https://')) {
        return frontendCanisterURL;
      }
      throw new Error(`Frontend URL is not HTTPS: ${frontendCanisterURL}`);
    default:
      throw new Error(`Not supported deep link type: ${deepLinkType}`);
  }
};
