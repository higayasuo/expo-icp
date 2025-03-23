import { Platform } from 'react-native';
import {
  WebSecureStorage,
  WebRegularStorage,
} from 'expo-storage-universal-web';
import {
  NativeSecureStorage,
  NativeRegularStorage,
} from 'expo-storage-universal-native';
import { AppKeyStorage, DelegationStorage } from 'expo-ii-integration';

console.log('Platform.OS', Platform.OS);

export const secureStorage =
  Platform.OS === 'web' ? new WebSecureStorage() : new NativeSecureStorage();

console.log(
  'secureStorage:native',
  secureStorage.constructor === NativeSecureStorage,
);

export const regularStorage =
  Platform.OS === 'web' ? new WebRegularStorage() : new NativeRegularStorage();

console.log(
  'regularStorage:native',
  regularStorage.constructor === NativeRegularStorage,
);

export const appKeyStorage = new AppKeyStorage(secureStorage);
export const delegationStorage = new DelegationStorage(regularStorage);
