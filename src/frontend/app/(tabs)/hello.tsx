import { View, Text } from 'react-native';

/**
 * Helloタブのコンポーネント
 * @returns {JSX.Element} Helloタブのコンポーネント
 */
export default function HelloTab() {
  return (
    <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
      <Text>Hello Tab</Text>
    </View>
  );
}
