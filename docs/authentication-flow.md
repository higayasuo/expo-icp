# Authentication Flow

This document explains the authentication flow in detail, including how Internet Identity authentication works in Expo apps.

For detailed diagrams and explanations of the authentication flow, please refer to the [official Internet Computer documentation](https://internetcomputer.org/docs/building-apps/security/iam#integrating-internet-identity-on-mobile-devices).

## Overview

The authentication flow consists of the following steps:

1. Expo app generates a SignIdentity (public-private key pair) and securely stores it
2. Expo app opens ii-integration in an external browser
3. ii-integration generates an intermediate session key
4. ii-integration authenticates with Internet Identity and passes the intermediate session key
5. Internet Identity returns a DelegationIdentity to ii-integration
6. ii-integration creates a DelegationChain with a 15-minute expiration and returns it to the Expo app
7. Expo app creates a DelegationIdentity using SignIdentity and DelegationChain
8. Expo app uses DelegationIdentity to communicate with the backend canister

## Detailed Flow

### 1. Expo App Generates SignIdentity

The Expo app generates a SignIdentity (public-private key pair).

### 2. Expo App Opens ii-integration

The Expo app opens ii-integration in an external browser, passing the public key and deep-link-type. This allows ii-integration to know the Expo app's public key, which it will use later when creating the delegation chain.

The `deep-link-type` parameter specifies how ii-integration returns to the Expo app, with the following 5 types:

- **icp**: When using Internet Computer frontend canister
- **expo-go**: When using Expo Go app
- **dev-server**: When using development server
- **modern**: When using Universal Links (iOS) or App Links (Android)
- **legacy**: When using custom URL schemes

### 3. ii-integration Generates Intermediate Session Key

ii-integration generates an intermediate session key. This intermediate session key is used in the authentication process with Internet Identity.

### 4. ii-integration Authenticates with Internet Identity

ii-integration authenticates with Internet Identity. During this process, it uses the intermediate session key.

### 5. Internet Identity Returns DelegationIdentity

Internet Identity returns a DelegationIdentity to ii-integration after successful authentication. This DelegationIdentity is issued for the intermediate session key.

### 6. ii-integration Returns DelegationChain to Expo App

ii-integration creates a DelegationChain with a 15-minute expiration and returns it to the Expo app. This DelegationChain is created using the intermediate session key and the Expo app's public key.

**Important**: The DelegationChain has a 15-minute expiration. After this period expires, the user needs to re-authenticate. This is an important security consideration.

#### Environment-specific DelegationChain Transmission

ii-integration transmits the delegation chain differently depending on the execution environment:

1. **Web Browser iframe Environment**:
   In a web browser iframe environment, it uses `window.parent.postMessage()` to send the delegation chain to the parent window (web app). This allows the web app to receive the delegation chain and complete authentication.

2. **Expo App Environment**:
   In an Expo app environment, it uses URI fragments (the part after `#`) to send the delegation chain. This ensures that the delegation chain is not sent to the server and is safely transmitted to the Expo app. This is an important security consideration:

3. **Benefits of URI Fragments**: URI fragments are not sent to the server when the browser resolves the URI. Unlike URL parameters or paths, this prevents the delegation chain from leaking to proxy app backends (IC boundary nodes or replica nodes).

4. **Security Enhancement**: This reduces the risk of malicious intermediate servers or boundary nodes intercepting the delegation chain. The delegation chain is processed only on the client side and is not sent to the server.

### 7. Expo App Creates DelegationIdentity

The Expo app creates a DelegationIdentity using the SignIdentity generated in step 1 and the DelegationChain returned from ii-integration.

### 8. Expo App Uses DelegationIdentity

The Expo app uses the created DelegationIdentity to communicate with the backend canister. This DelegationIdentity contains authentication information from Internet Identity and is used by the backend canister to identify the user.

## Security Considerations

The authentication flow includes several security considerations:

1. **Private Key Protection**:

   - **Native Environment**: SignIdentity private keys are stored in secure storage.
   - **Web Environment**: SignIdentity private keys are stored in sessionStorage. While not as secure as the Native environment, security measures such as Content Security Policy (CSP) are implemented to protect against XSS attacks.

2. **Intermediate Session Key**: An intermediate session key is used to enhance security. This key is created as an unextractable key using the WebCrypto API and should be short-lived.

3. **DelegationChain Validation**: The DelegationChain must be validated before use by confirming that the public key of SignIdentity matches the public key of the DelegationChain. This ensures that the correct delegation chain is being used.

   **Important**: The agent being used may not verify whether the generated session key corresponds to the delegation found in the delegation chain. Using such an agent to make a signed update call would create a message containing the provided delegation chain and sign it with a mismatching key. Obviously, the IC would reject such a message because the signature doesn't correspond to the delegation chain, but the delegation chain would have already leaked to boundary nodes and replica nodes, making it vulnerable to theft by attackers. Therefore, it is essential to verify the delegation chain before using it.

4. **Origin Verification**: When using postMessage, ii-integration verifies the origin of authentication requests and issues delegations only for specific frontend origins. This prevents delegations from leaking to unintended origins.

5. **Session Timeout**: The DelegationChain expires after 15 minutes, requiring user re-authentication.

6. **URI Fragment Usage**: The delegation chain is transmitted using URI fragments (the part after `#`), ensuring it is not sent to the server. This prevents the delegation chain from leaking to proxy app backends (IC boundary nodes or replica nodes).

7. **Application Links/Universal Links Usage**: The delegation chain is returned to the mobile app using Android App Links or iOS Universal Links. This binds the domain name/hostname to the mobile app, preventing attackers from using malicious mobile apps to receive the delegation chain.
