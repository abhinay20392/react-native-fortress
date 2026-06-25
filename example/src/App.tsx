import { useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { DeviceIntegrityScreen } from './screens/DeviceIntegrityScreen';
import { SslPinningDemoScreen } from './screens/SslPinningDemoScreen';
import { TamperMonitorScreen } from './screens/TamperMonitorScreen';

type Screen = 'integrity' | 'tamper' | 'ssl';

const TABS: { id: Screen; label: string }[] = [
  { id: 'integrity', label: 'Integrity' },
  { id: 'tamper', label: 'Tamper' },
  { id: 'ssl', label: 'SSL' },
];

export default function App() {
  const [screen, setScreen] = useState<Screen>('integrity');

  return (
    <View style={styles.root}>
      <View style={styles.tabs}>
        {TABS.map((tab) => (
          <Pressable
            key={tab.id}
            style={[styles.tab, screen === tab.id && styles.tabActive]}
            onPress={() => setScreen(tab.id)}
          >
            <Text
              style={[
                styles.tabText,
                screen === tab.id && styles.tabTextActive,
              ]}
            >
              {tab.label}
            </Text>
          </Pressable>
        ))}
      </View>

      {screen === 'integrity' ? (
        <DeviceIntegrityScreen />
      ) : screen === 'tamper' ? (
        <TamperMonitorScreen />
      ) : (
        <SslPinningDemoScreen />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
    backgroundColor: '#0f172a',
  },
  tabs: {
    flexDirection: 'row',
    paddingHorizontal: 16,
    paddingTop: 56,
    paddingBottom: 8,
    gap: 8,
  },
  tab: {
    flex: 1,
    paddingVertical: 10,
    borderRadius: 8,
    backgroundColor: '#1e293b',
    alignItems: 'center',
  },
  tabActive: {
    backgroundColor: '#2563eb',
  },
  tabText: {
    color: '#94a3b8',
    fontWeight: '600',
    fontSize: 12,
  },
  tabTextActive: {
    color: '#ffffff',
  },
});
