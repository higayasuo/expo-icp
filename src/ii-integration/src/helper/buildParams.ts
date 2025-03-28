import { SignIdentity } from '@dfinity/agent';
import { buildIdentity } from './buildIdentity';
import { buildIIUri } from './buildIIUri';
import { buildRedirectUri } from './buildRedirectUri';

/**
 * Interface representing the result of the buildParams function.
 */
interface BuildParamsResult {
  identity: SignIdentity;
  iiUri: string;
  redirectUri: string;
}

/**
 * Builds the parameters required for the application.
 *
 * @returns {BuildParamsResult} The built parameters including identity, iiUri, and redirectUri.
 * @throws Will throw an error if pubkey or environment is missing in the query string.
 */
export const buildParams = (): BuildParamsResult => {
  const url = new URL(window.location.href);
  const pubKey = url.searchParams.get('pubkey');
  const environment = url.searchParams.get('environment');

  if (!pubKey || !environment) {
    throw new Error('Missing pubkey or environment in query string');
  }

  const identity = buildIdentity(pubKey);
  const iiUri = buildIIUri();
  const redirectUri = buildRedirectUri(environment);

  return { identity, iiUri, redirectUri };
};
