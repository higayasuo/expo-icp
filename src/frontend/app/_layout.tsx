import FontAwesome from '@expo/vector-icons/FontAwesome';
import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect, useMemo } from 'react';
import 'react-native-reanimated';
import { useIIIntegration, IIIntegrationProvider } from 'expo-ii-integration';
import { ErrorProvider } from '@/contexts/ErrorContext';
import { View, ActivityIndicator } from 'react-native';
import Constants from 'expo-constants';
import * as Linking from 'expo-linking';

console.log(JSON.stringify(Constants.executionEnvironment, null, 2));
console.log('Linking.createURL("/")', Linking.createURL('/'));

import { useError } from '@/contexts/ErrorContext';
import {
  LOCAL_IP_ADDRESS,
  DFX_NETWORK,
  CANISTER_ID_II_INTEGRATION,
  CANISTER_ID_FRONTEND,
} from '@/constants';
import { delegationStorage, appKeyStorage } from '@/storage';
//import { useAesKey, AesProcessingView } from '@/aes';

export const unstable_settings = {
  // Ensure that reloading on `/modal` keeps a back button present.
  initialRouteName: '(tabs)',
};

// Prevent the splash screen from auto-hiding before asset loading is complete.
SplashScreen.preventAutoHideAsync();

export default function RootLayout() {
  const [loaded, error] = useFonts({
    ...FontAwesome.font,
  });

  // Expo Router uses Error Boundaries to catch errors in the navigation tree.
  useEffect(() => {
    if (error) throw error;
  }, [error]);

  useEffect(() => {
    if (loaded) {
      SplashScreen.hideAsync();
    }
  }, [loaded]);

  if (!loaded) {
    return <LoadingView />;
  }

  return (
    <ErrorProvider>
      <RootLayoutNav />
    </ErrorProvider>
  );
}

function RootLayoutNav() {
  const iiIntegration = useIIIntegration({
    localIPAddress: LOCAL_IP_ADDRESS,
    dfxNetwork: DFX_NETWORK,
    executionEnvironment: Constants.executionEnvironment,
    frontendCanisterId: CANISTER_ID_FRONTEND,
    iiIntegrationCanisterId: CANISTER_ID_II_INTEGRATION,
    appKeyStorage,
    delegationStorage,
  });

  const { authError, isReady } = iiIntegration;
  const { showError } = useError();

  useEffect(() => {
    if (authError) {
      showError(authError);
    }
  }, [authError, showError]);

  // Memoize the main content view to prevent recreation on each render
  const mainContentView = useMemo(
    () => (
      <IIIntegrationProvider value={iiIntegration}>
        <Stack
          screenOptions={{
            headerShown: false,
          }}
        >
          <Stack.Screen name="(tabs)" />
        </Stack>
      </IIIntegrationProvider>
    ),
    [iiIntegration],
  );

  if (!isReady) {
    return <LoadingView />;
  }

  return mainContentView;
}

const LoadingView = () => {
  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <ActivityIndicator size="large" />
    </View>
  );
};
