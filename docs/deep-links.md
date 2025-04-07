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

## Setup Process

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

### 4. Create assetlinks.json

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

This file will be used to verify your app's association with your domain for App Links.

### 5. Build Android Preview

For Android, build a preview version of your app:

```bash
npm run frontend:eas:build:android:preview
```

This will create a build of your app that you can use for testing App Links.

### 6. Get SHA-256 Fingerprint

After building, retrieve the SHA-256 fingerprint of your app's signing certificate:

```bash
npm run frontend:eas:credentials
```

Look for the SHA-256 fingerprint in the output and update the `assetlinks.json` file with this value.

### 7. Deploy to Internet Computer

Deploy your application to the Internet Computer:

```bash
npm run dfx:deploy:ic
```

This will deploy your application, including the `.well-known/assetlinks.json` file, which is necessary for App Links verification.

## iOS Universal Links Setup

For iOS Universal Links, you can use the `npx setup-safari` command to automate the setup process:

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

You should also add the following meta tag to the `<head>` of your website (app/+html.tsx in Expo Router):

```html
<meta name="apple-itunes-app" content="app-id=YOUR_ITUNES_ID" />
```

Replace `YOUR_ITUNES_ID` with the iTunes ID provided by the setup-safari command.

### Manual Setup (Alternative)

If you prefer to set up Universal Links manually, you need to:

1. Create an Apple Developer account if you don't have one
2. Configure Associated Domains in your Apple Developer account
3. Create an `apple-app-site-association` file and deploy it to your domain
4. Add the apple-itunes-app meta tag to your website

You should add the following meta tag to the `<head>` of your website (app/+html.tsx in Expo Router):

```html
<meta name="apple-itunes-app" content="app-id=YOUR_ITUNES_ID" />
```

Replace `YOUR_ITUNES_ID` with your app's iTunes ID from App Store Connect.

### Creating apple-app-site-association

Create a file at `src/frontend/public/.well-known/apple-app-site-association` with the following content:

```json
{
  "applinks": {
    "apps": [],
    "details": [
      {
        "appID": "YOUR_TEAM_ID.com.example.expoicp",
        "paths": ["*"]
      }
    ]
  },
  // This section enables Apple Handoff
  "activitycontinuation": {
    "apps": ["YOUR_TEAM_ID.com.example.expoicp"]
  },
  // This section enable Shared Web Credentials
  "webcredentials": {
    "apps": ["YOUR_TEAM_ID.com.example.expoicp"]
  }
}
```

Replace `YOUR_TEAM_ID` with your Apple Developer Team ID and `com.example.expoicp` with your actual bundle ID (which should match the `expo.ios.bundleIdentifier` in your app.json).

## Testing App Links / Universal Links

### Android

1. Install the app on your device
2. Open the app and tap the login button
3. Complete the authentication process in the browser
4. If App Links are properly configured, the app should receive the delegation chain and complete authentication
5. If App Links are not properly configured, you'll be redirected to the web version of the app

### iOS

1. Install the app on your device
2. Open the app and tap the login button
3. Complete the authentication process in the browser
4. If Universal Links are properly configured, the app should receive the delegation chain and complete authentication
5. If Universal Links are not properly configured, you'll be redirected to the web version of the app

## Troubleshooting

### Android App Links

- Verify that your `assetlinks.json` file is correctly deployed and accessible
- Check that the SHA-256 fingerprint matches your app's signing certificate
- Ensure your app's package name matches the one in `assetlinks.json`

### iOS Universal Links

- Verify that your `apple-app-site-association` file is correctly deployed and accessible
- Check that your Associated Domains capability is enabled in your Apple Developer account
- Ensure your app's bundle identifier matches the one in `apple-app-site-association`

## Additional Resources

- [Expo EAS Documentation](https://docs.expo.dev/build/introduction/)
- [Android App Links Documentation](https://developer.android.com/training/app-links)
- [iOS Universal Links Documentation](https://developer.apple.com/ios/universal-links/)
