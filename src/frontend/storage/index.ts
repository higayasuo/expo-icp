import { Platform } from 'react-native';
import {
  WebSecureStorage,
  WebRegularStorage,
} from 'expo-storage-universal-web';
import {
  NativeSecureStorage,
  NativeRegularStorage,
} from 'expo-storage-universal-native';
import {
  AppKeyStorage,
  DelegationStorage,
  RedirectPathStorage,
} from 'expo-ii-integration';

export const secureStorage =
  Platform.OS === 'web' ? new WebSecureStorage() : new NativeSecureStorage();

export const regularStorage =
  Platform.OS === 'web' ? new WebRegularStorage() : new NativeRegularStorage();

export const appKeyStorage = new AppKeyStorage(secureStorage);
export const delegationStorage = new DelegationStorage(secureStorage);
export const redirectPathStorage = new RedirectPathStorage(regularStorage);
