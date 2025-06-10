import FontAwesome from '@expo/vector-icons/FontAwesome';
import { useFonts } from 'expo-font';
import { Stack } from 'expo-router';
import * as SplashScreen from 'expo-splash-screen';
import { useEffect, useMemo } from 'react';
import 'react-native-reanimated';
import { useIIIntegration, IIIntegrationProvider } from 'expo-ii-integration';
import { buildAppConnectionURL } from 'expo-icp-app-connect-helpers';
import { compareUint8Arrays, getDeepLinkType } from 'expo-icp-frontend-helpers';
import { ErrorToastProvider, useErrorToast } from 'expo-error-toast';
import { View, ActivityIndicator } from 'react-native';
import * as Linking from 'expo-linking';
import * as jose from 'jose';

import {
  LOCAL_IP_ADDRESS,
  DFX_NETWORK,
  CANISTER_ID_II_INTEGRATION,
  CANISTER_ID_FRONTEND,
} from '@/constants';
import { secureStorage, regularStorage } from '@/storage';
import { cryptoModule } from '@/crypto';

import {
  createP256,
  createP384,
  createP521,
  createEd25519,
  createSecp256k1,
  createBls12_381,
} from 'noble-curves-extended';
import { bls12_381 as bls12_381_noble } from '@noble/curves/bls12-381';

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
    <ErrorToastProvider>
      <RootLayoutNav />
    </ErrorToastProvider>
  );
}

function RootLayoutNav() {
  const b64u = jose.base64url.encode(new Uint8Array([1, 2, 3]));
  console.log('b64u', b64u);
  console.log('decoded b64u', jose.base64url.decode(b64u));
  const randomBytes = cryptoModule.getRandomBytes;
  const p256 = createP256(randomBytes);
  const p384 = createP384(randomBytes);
  const p521 = createP521(randomBytes);
  const ed25519 = createEd25519(randomBytes);
  const secp256k1 = createSecp256k1(randomBytes);
  const bls12_381 = createBls12_381(randomBytes);

  const message = new TextEncoder().encode('test message');

  const p256PrivateKey = p256.utils.randomPrivateKey();
  const p256PublicKey = p256.getPublicKey(p256PrivateKey);
  const p256Signature = p256.sign(message, p256PrivateKey);
  const p256IsValid = p256.verify(p256Signature, message, p256PublicKey);
  console.log('p256 is valid', p256IsValid);

  const p384PrivateKey = p384.utils.randomPrivateKey();
  const p384PublicKey = p384.getPublicKey(p384PrivateKey);
  const p384Signature = p384.sign(message, p384PrivateKey);
  const p384IsValid = p384.verify(p384Signature, message, p384PublicKey);
  console.log('p384 is valid', p384IsValid);

  const p521PrivateKey = p521.utils.randomPrivateKey();
  const p521PublicKey = p521.getPublicKey(p521PrivateKey);
  const p521Signature = p521.sign(message, p521PrivateKey);
  const p521IsValid = p521.verify(p521Signature, message, p521PublicKey);
  console.log('p521 is valid', p521IsValid);

  const ed25519PrivateKey = ed25519.utils.randomPrivateKey();
  const ed25519PublicKey = ed25519.getPublicKey(ed25519PrivateKey);
  const ed25519Signature = ed25519.sign(message, ed25519PrivateKey);
  const ed25519IsValid = ed25519.verify(
    ed25519Signature,
    message,
    ed25519PublicKey,
  );
  console.log('ed25519 is valid', ed25519IsValid);

  const secp256k1PrivateKey = secp256k1.utils.randomPrivateKey();
  const secp256k1PublicKey = secp256k1.getPublicKey(secp256k1PrivateKey);
  const secp256k1Signature = secp256k1.sign(message, secp256k1PrivateKey);
  const secp256k1IsValid = secp256k1.verify(
    secp256k1Signature,
    message,
    secp256k1PublicKey,
  );
  const recovered = compareUint8Arrays(
    secp256k1Signature.recoverPublicKey(message).toRawBytes(),
    secp256k1PublicKey,
  );
  console.log('secp256k1 is valid', secp256k1IsValid);
  console.log('recovered', recovered);

  const bls12_381PrivateKey = bls12_381.utils.randomPrivateKey();
  const bls12_381PublicKey = bls12_381_noble.getPublicKey(bls12_381PrivateKey);
  const bls12_381Signature = bls12_381_noble.sign(message, bls12_381PrivateKey);
  const bls12_381IsValid = bls12_381_noble.verify(
    bls12_381Signature,
    message,
    bls12_381PublicKey,
  );
  console.log('bls12_381 is valid', bls12_381IsValid);

  const deepLink = Linking.createURL('/');
  const iiIntegrationUrl = buildAppConnectionURL({
    dfxNetwork: DFX_NETWORK,
    localIPAddress: LOCAL_IP_ADDRESS,
    targetCanisterId: CANISTER_ID_II_INTEGRATION,
  });
  const deepLinkType = getDeepLinkType({
    deepLink,
    frontendCanisterId: CANISTER_ID_FRONTEND,
    easDeepLinkType: process.env.EXPO_PUBLIC_EAS_DEEP_LINK_TYPE,
  });
  const iiIntegration = useIIIntegration({
    iiIntegrationUrl,
    deepLinkType,
    secureStorage,
    regularStorage,
    cryptoModule,
  });

  const { authError, isAuthReady } = iiIntegration;
  const { showError } = useErrorToast();

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

  if (!isAuthReady) {
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
