# Frontend Implementation

This directory contains the frontend implementation of the expo-icp project, which provides Internet Identity authentication for Expo apps.

## Overview

The frontend is built using:

- Expo
- React Native
- TypeScript
- Internet Computer Protocol (ICP)

## Setup

1. Install dependencies and setup Expo:

```bash
npm run setup
```

2. Start the development server:

```bash
npm start
```

3. For development with dev client:

```bash
npm run start:dev-client
```

4. Setup environment variables:

```bash
npm run setup-env
```

## Development

- The frontend uses Expo Router for navigation
- TypeScript is used for type safety
- React Native components are used for UI elements
- Internet Identity is integrated for authentication
- Error handling is managed through a context provider

## Testing

Tests are run using Vitest:

- Run tests:

```bash
npm test
```

- Run tests in watch mode:

```bash
npm run test:watch
```

- Run tests with coverage:

```bash
npm run test:coverage
```

## Building

### Web Build

```bash
npm run build
```

### iOS Build

1. Initialize EAS (if not done):

```bash
npm run eas:init
```

2. Setup credentials:

```bash
npm run eas:credentials
```

3. Build for preview:

```bash
npm run eas:build:ios:preview
```

4. Build for production:

```bash
npm run eas:build:ios:production
```

### Android Build

1. Initialize EAS (if not done):

```bash
npm run eas:init
```

2. Setup credentials:

```bash
npm run eas:credentials
```

3. Build for preview:

```bash
npm run eas:build:android:preview
```

4. Build for production:

```bash
npm run eas:build:android:production
```

## Contributing

Please follow the project's coding standards and submit pull requests for any improvements.
