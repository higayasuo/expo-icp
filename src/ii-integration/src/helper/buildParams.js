import { buildIdentity } from './buildIdentity';
import { buildIIUri } from './buildIIUri';
import { buildRedirectUri } from './buildRedirectUri';
/**
 * Builds the parameters required for the application.
 *
 * @returns {BuildParamsResult} The built parameters including identity, iiUri, and redirectUri.
 * @throws Will throw an error if pubkey or environment is missing in the query string.
 */
export const buildParams = () => {
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
