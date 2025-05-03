import { Pressable, Text, StyleSheet } from 'react-native';
import { buttonTextStyles } from './styles';
import { useIIIntegrationContext } from 'expo-ii-integration';
import { useState } from 'react';
import { useError } from '@/contexts/ErrorContext';
/**
 * Component that handles the logout functionality
 */
export const LogOut = () => {
  const { logout } = useIIIntegrationContext();
  const [busy, setBusy] = useState(false);
  const { showError } = useError();

  const handleLogout = async () => {
    setBusy(true);
    try {
      await logout();
    } catch (error) {
      showError(error);
    } finally {
      setBusy(false);
    }
  };

  return (
    <Pressable
      style={[styles.headerButton, busy && styles.disabled]}
      accessibilityRole="button"
      disabled={busy}
      accessibilityState={{ busy }}
      onPress={handleLogout}
    >
      <Text style={styles.headerButtonText}>Log out</Text>
    </Pressable>
  );
};

const styles = StyleSheet.create({
  headerButton: {
    marginRight: 15,
  },
  headerButtonText: {
    ...buttonTextStyles,
    color: '#007AFF',
  },
  disabled: {
    opacity: 0.5,
  },
});
