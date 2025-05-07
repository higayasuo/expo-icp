import { WebCryptoModule } from 'expo-crypto-universal-web';
import { NativeCryptoModule } from 'expo-crypto-universal-native';
import { isWeb, CryptoModule } from 'expo-crypto-universal';

export const cryptoModule: CryptoModule = isWeb()
  ? new WebCryptoModule()
  : new NativeCryptoModule();
