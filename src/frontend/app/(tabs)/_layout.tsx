import React from 'react';
import FontAwesome from '@expo/vector-icons/FontAwesome';
import { Tabs } from 'expo-router';
import { LogIn } from '@/components/LogIn';
import { LogOut } from '@/components/LogOut';
import { useIIIntegrationContext } from 'expo-ii-integration';

/**
 * You can explore the built-in icon families and icons on the web at https://icons.expo.fyi/
 */
function TabBarIcon(props: {
  name: React.ComponentProps<typeof FontAwesome>['name'];
  color: string;
}) {
  return <FontAwesome size={28} style={{ marginBottom: -3 }} {...props} />;
}

export default function TabLayout() {
  const { isAuthenticated } = useIIIntegrationContext();

  return (
    <Tabs
      screenOptions={{
        tabBarActiveTintColor: '#007AFF',
        headerRight: () => (isAuthenticated ? <LogOut /> : <LogIn />),
        headerStyle: {
          height: 110,
        },
      }}
    >
      <Tabs.Screen
        name="index"
        options={{
          title: 'Identity',
          tabBarIcon: ({ color }) => <TabBarIcon name="user" color={color} />,
        }}
      />
      <Tabs.Screen
        name="hello"
        options={{
          title: 'Hello',
          tabBarIcon: ({ color }) => (
            <TabBarIcon name="smile-o" color={color} />
          ),
        }}
      />
    </Tabs>
  );
}
