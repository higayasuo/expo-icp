# `expo-icp`

Welcome to the `expo-icp` project.
The Japanese version is available [here](README_ja.md).

## Demo

<a href="https://csbju-6qaaa-aaaag-at7da-cai.icp0.io/?v=1" target="_blank" rel="noopener noreferrer">https://csbju-6qaaa-aaaag-at7da-cai.icp0.io/</a>
(Ctrl+Click or ⌘+Click to open in new tab)

### Screen shots

- iPhone
  ![iPhone](./docs/images/iphone.jpeg)

- Xperia
  ![Xperia](./docs/images/xperia.png)

## Service Concept

A multi-platform(iOS/Android/Web) authentication solution that makes Internet Identity easy to use in Expo apps with just a few lines of code. This project also provides a template for creating smartphone native apps for ICP, which have been rare until now.

## Target Users

- Cross-platform developers for Web/Native
- Developers looking to build applications on Internet Computer Protocol (ICP)
- Mobile app developers who need to implement secure authentication systems

## Benefits and Features

- Easy implementation of Internet Identity authentication in smartphone native apps, which was previously difficult
- Use the same library for Internet Identity authentication in both Expo Web and Native
- Provide consistent authentication experience across multiple platforms (Web/iOS/Android)
- Simplify the workflow from development environment to deployment

## Implementation Guide

You can implement Internet Identity authentication with these simple steps:

1. **Set up Authentication Provider**: Configure the provider in your app entry file

```typescript
// Set up IIIntegrationProvider in app/_layout.tsx
import { useIIIntegration, IIIntegrationProvider } from 'expo-ii-integration';

const auth = useIIIntegration({
  localIPAddress: LOCAL_IP_ADDRESS,
  dfxNetwork: ENV_VARS.DFX_NETWORK,
  iiIntegrationCanisterId: ENV_VARS.CANISTER_ID_II_INTEGRATION,
  iiCanisterId: ENV_VARS.CANISTER_ID_INTERNET_IDENTITY,
});

return <IIIntegrationProvider value={auth}>...</IIIntegrationProvider>;
```

2. **Implement Login Functionality**: Add login feature with just a few lines

```typescript
// Use login function in components/LogIn.tsx
import { useIIIntegrationContext } from 'expo-ii-integration';

const { login } = useIIIntegrationContext();

await login();
```

3. **Implement Logout Functionality**: Add logout feature just as easily

```typescript
// Use logout function in components/LogOut.tsx
import { useIIIntegrationContext } from 'expo-ii-integration';

const { logout } = useIIIntegrationContext();

await logout();
```

4. **Backend Integration**: Call backend Canister using authenticated identity

```typescript
// Call backend Canister in components/WhoAmI.tsx
import { useIIIntegrationContext } from 'expo-ii-integration';
import { createBackend } from '@/backend';

const { identity } = useIIIntegrationContext();

const backend = createBackend(identity);
await backend.whoami();
```

## How We're Using ICP's Mechanisms

- Password-free secure authentication through "Internet Identity (II)"
  - Compliant with the latest authentication standards using WebAuthn/passkeys
  - Secure sharing of authentication information across multiple devices
- Full-stack environment through integration with ICP backend
  - Automatic authentication integration when calling backend
  - Full-stack environment without relying on cloud services
- Backend processing using WebAssembly-based unified execution environment
  - ICP canisters (backend) running on WebAssembly
  - Fast and secure server processing

## Why We Chose to Develop with ICP and Its Advantages

Traditional passkey authentication systems require server-side implementation. Custom implementation is not only costly but also carries security risks. Using Internet Identity's proven passkey authentication reduces security risks and cuts costs.

Moreover, Internet Identity authentication is integrated with caller authentication for backend Canisters. Not having to implement this yourself offers significant advantages in terms of both security and cost.

### Key Benefits

- **Enhanced Security**: Reduce risks by using a proven authentication system
- **Reduced Development Costs**: Significantly cut costs for implementing and maintaining authentication systems
- **Improved User Experience**: Provide a secure and simple passwordless authentication experience
- **Integrated Environment**: Maintain consistent authentication flow from frontend to backend

## Libraries Developed for This Project

- [expo-ii-integration](https://github.com/higayasuo/expo-ii-integration) - Library for accessing Internet Identity from Expo Web/Native
- [@higayasuo/iframe-messenger](https://github.com/higayasuo/iframe-messenger) - Library for type-safe message communication via iframe
- [canister-manager](https://github.com/higayasuo/canister-manager) - Library that resolves canister URL issues that depend on the environment
- [expo-storage-universal](https://github.com/higayasuo/expo-storage-universal) - Base library for unified access to storage from Web/Native
- [expo-storage-universal-web](https://github.com/higayasuo/expo-storage-universal-web) - Web implementation of expo-storage-universal
- [expo-storage-universal-native](https://github.com/higayasuo/expo-storage-universal-native) - Native implementation of expo-storage-universal

## Documentation

- [Authentication Flow](docs/architecture/authentication-flow.md)
- [Setup guide](docs/setup.md)

## Repository Commits

You can check the development history of each repository from the links below. Refer to these if you want to track implementation details or change history:

- [expo-icp](https://github.com/higayasuo/expo-icp/commits?author=higayasuo)
- [expo-ii-integration](https://github.com/higayasuo/expo-ii-integration/commits?author=higayasuo)
- [@higayasuo/iframe-messenger](https://github.com/higayasuo/iframe-messenger/commits?author=higayasuo)
- [canister-manager](https://github.com/higayasuo/canister-manager/commits?author=higayasuo)
- [expo-storage-universal](https://github.com/higayasuo/expo-storage-universal/commits?author=higayasuo)
- [expo-storage-universal-web](https://github.com/higayasuo/expo-storage-universal-web/commits?author=higayasuo)
- [expo-storage-universal-native](https://github.com/higayasuo/expo-storage-universal-native/commits?author=higayasuo)
