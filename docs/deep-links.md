# App Links / Universal Links Setup

This document explains how to set up App Links (Android) and Universal Links (iOS) for this project. These features allow your app to handle deep links from ii-integration.

## Overview

App Links (Android) and Universal Links (iOS) are essential for the authentication flow in native mobile applications. Their primary role is to enable your app to receive callbacks from ii-integration after the user has authenticated with Internet Identity. Without proper deep link configuration, the authentication flow would be broken as the app wouldn't be able to receive the delegation chain from ii-integration.

## How Deep Links Work in This Project

In this project, deep links are not used to launch the app directly from the browser's address bar. Instead, they serve a specific purpose in the authentication flow:

1. The user opens the app and taps the login button
2. The app opens ii-integration in an external browser
3. The user authenticates with Internet Identity
4. ii-integration attempts to return to the app using deep links
5. If deep links are properly configured, the app receives the delegation chain and completes authentication
6. If deep links are not properly configured, ii-integration will redirect to the web version of the app instead

This is why proper deep link configuration is crucial for the native app authentication flow to work correctly.

## Common Setup Steps

### 1. Install EAS CLI

First, install the EAS CLI globally:

```bash
npm install -g eas-cli
```

### 2. Initialize EAS Project

Run the following command to initialize the EAS project:

```bash
npm run frontend:eas:init
```

This will set up the necessary EAS configuration files for your project.

### 3. Configure app.json

Update your `app.json` file to include the necessary configuration for App Links and Universal Links:

```json
{
  "expo": {
    "scheme": "expo-icp",
    "ios": {
      "bundleIdentifier": "com.example.expoicp",
      "associatedDomains": ["applinks:bsbsa-xaaaa-aaaai-q3wja-cai.icp0.io"],
      "infoPlist": {
        "NSAppTransportSecurity": {
          "NSAllowsArbitraryLoads": true,
          "NSAllowsLocalNetworking": true
        }
      }
    },
    "android": {
      "package": "com.example.expoicp",
      "intentFilters": [
        {
          "action": "VIEW",
          "autoVerify": true,
          "data": [
            {
              "scheme": "https",
              "host": "bsbsa-xaaaa-aaaai-q3wja-cai.icp0.io",
              "pathPrefix": "/"
            }
          ],
          "category": ["BROWSABLE", "DEFAULT"]
        }
      ]
    }
  }
}
```

Key points:

- The `scheme` defines your app's custom URL scheme
- For Android, `intentFilters` with `autoVerify: true` enable App Links
- The `host` should match your frontend canister domain (e.g., `[canister-id].icp0.io`)
- **Note**: The `host` value is automatically updated by the `setup-env.js` script when deploying to the Internet Computer
- For iOS, the `associatedDomains` entry is also automatically updated by the `setup-env.js` script when deploying to the Internet Computer
- **Important**: It's recommended to use the same value for both `expo.ios.bundleIdentifier` and `expo.android.package` (e.g., `com.example.expoicp`). This makes it easier to manage your app's identity across platforms and simplifies the configuration of deep links.

## Android App Links Setup

### 1. Create assetlinks.json

Create a file at `src/frontend/public/.well-known/assetlinks.json` with the following content:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.expoicp",
      "sha256_cert_fingerprints": ["YOUR_SHA256_FINGERPRINT_WILL_BE_ADDED_HERE"]
    }
  }
]
```

**Important**: The `package_name` in this file must exactly match the `expo.android.package` value in your `app.json` file. If these values don't match, App Links verification will fail.

### 2. Build Android Preview

Build a preview version of your app:

```bash
npm run frontend:eas:build:android:preview
```

This will create a build of your app that you can use for testing App Links.

### 3. Get SHA-256 Fingerprint

After building, retrieve the SHA-256 fingerprint of your app's signing certificate:

```bash
npm run frontend:eas:credentials
```

You'll be prompted to select a platform and a build profile. Use the arrow keys to navigate and press Enter to select:

1. Select **Android** (not iOS)
2. Select **preview** (not development or production)

Look for the SHA-256 fingerprint in the output and update the `assetlinks.json` file with this value.

Example output:

```
Android
  Preview
    Keystore: /Users/username/.expo/android-keystore.jks
    Keystore password: android
    Key alias: upload
    Key password: android
    SHA-1: 5E:8F:16:06:2E:A3:CD:2C:4A:0D:54:78:76:BA:A6:F3:8C:AB:F6:25
    SHA-256: 79:7C:CA:05:35:DA:88:40:80:EA:AE:3C:5A:79:11:33:01:D7:8B:06:FE:CC:E7:13:5C:B9:FA:A1:39:93:21:59
```

Update your `assetlinks.json` file with the SHA-256 fingerprint:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.expoicp",
      "sha256_cert_fingerprints": [
        "79:7C:CA:05:35:DA:88:40:80:EA:AE:3C:5A:79:11:33:01:D7:8B:06:FE:CC:E7:13:5C:B9:FA:A1:39:93:21:59"
      ]
    }
  }
]
```

### 4. Deploy to Internet Computer

After updating the `assetlinks.json` file with the SHA-256 fingerprint, deploy your application:

```bash
npm run dfx:deploy:ic
```

This will deploy your application, including the `.well-known/assetlinks.json` file, which is necessary for App Links verification.

### 5. Install the App

After deploying, install the app on your device and test the App Links functionality.

## iOS Universal Links Setup

### 1. Register iOS Device

Before building a preview version for iOS, you need to register your device:

```bash
npm run frontend:eas:device:create
```

This command will:

- Log in to your Apple Developer account
- Register your device with Apple
- Generate a provisioning profile for your device

Follow the prompts to complete the registration process. This step is required for both preview and development builds on iOS devices.

For more detailed information about registering iOS devices with EAS, refer to the [Expo documentation on iOS device registration](https://docs.expo.dev/tutorial/eas/ios-development-build-for-devices/#provisioning-profile).

### 2. Create apple-app-site-association

Instead of manually creating the apple-app-site-association file, use the `npx setup-safari` command to automate the setup process:

```bash
npx setup-safari
```

This command will:

1. Log in to your Apple Developer account
2. Enable associated domains for your app
3. Create the necessary app entry in App Store Connect
4. Generate the apple-app-site-association file with the correct format

After running the command, you'll receive:

- Your Team ID
- iTunes ID
- Bundle ID
- The content for your apple-app-site-association file

Copy the generated apple-app-site-association content to `src/frontend/public/.well-known/apple-app-site-association`.

### 3. Deploy to Internet Computer

**IMPORTANT**: For iOS Universal Links to work, you must deploy the apple-app-site-association file to the Internet Computer BEFORE installing the app on your device:

```bash
npm run dfx:deploy:ic
```

This will deploy your application, including the `.well-known/apple-app-site-association` file, which is necessary for Universal Links verification.

### 4. Build iOS Preview

Build a preview version of your app:

```bash
npm run frontend:eas:build:ios:preview
```

This will create a build of your app that you can use for testing Universal Links.

### 5. Install the App

After deploying and building, install the app on your device and test the Universal Links functionality.

## Testing App Links / Universal Links

### Testing Deep Links

1. Install the app on your device
2. Open the app and tap the login button
3. Complete the authentication process in the browser
4. If deep links are properly configured, the app should receive the delegation chain and complete authentication
5. If deep links are not properly configured, you'll be redirected to the web version of the app

## Additional Resources

- [EAS Tutorial: Introduction](https://docs.expo.dev/tutorial/eas/introduction/)
- [Expo Android App Links](https://docs.expo.dev/linking/android-app-links/)
- [Expo iOS Universal Links](https://docs.expo.dev/linking/ios-universal-links/)
