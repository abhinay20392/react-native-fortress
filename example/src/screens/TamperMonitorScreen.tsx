import { useCallback, useEffect, useState } from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { Fortress } from 'react-native-fortress';
import type { FortressStatus, ThreatEvent } from 'react-native-fortress';
import { configureExampleFortress } from '../fortressConfig';

function formatTimestamp(ms: number): string {
  return new Date(ms).toLocaleTimeString();
}

function severityColor(severity: ThreatEvent['severity']): string {
  switch (severity) {
    case 'critical':
      return '#f87171';
    case 'high':
      return '#fb923c';
    case 'medium':
      return '#fbbf24';
    default:
      return '#38bdf8';
  }
}

export function TamperMonitorScreen() {
  const [status, setStatus] = useState<FortressStatus | null>(null);
  const [liveThreats, setLiveThreats] = useState<ThreatEvent[]>([]);
  const [listening, setListening] = useState(false);
  const [tamperEnabled, setTamperEnabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const refreshStatus = useCallback(async () => {
    try {
      const nextStatus = await Fortress.getStatus();
      setStatus(nextStatus);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    }
  }, []);

  useEffect(() => {
    const bootstrap = async () => {
      try {
        // Start with tamper off in __DEV__ so opening this tab under a debugger is quiet.
        await configureExampleFortress({
          pollIntervalMs: 10_000,
          checks: {
            tamper: false,
            root: false,
            jailbreak: false,
          },
        });
        await Fortress.stopMonitoring();
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to configure Fortress'
        );
      } finally {
        setLoading(false);
      }

      await refreshStatus();
    };

    bootstrap();
  }, [refreshStatus]);

  const enableTamperMonitoring = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      await configureExampleFortress({
        monitor: true,
        pollIntervalMs: 10_000,
        checks: {
          tamper: true,
          root: false,
          jailbreak: false,
        },
      });
      await Fortress.startMonitoring();
      setTamperEnabled(true);
      await refreshStatus();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Failed to enable tamper monitoring'
      );
    } finally {
      setLoading(false);
    }
  }, [refreshStatus]);

  useEffect(() => {
    const subscription = Fortress.addThreatListener((event) => {
      setLiveThreats((current) => [event, ...current].slice(0, 50));
    });

    setListening(true);

    return () => {
      subscription.remove();
      setListening(false);
    };
  }, []);

  useEffect(() => {
    const interval = setInterval(() => {
      refreshStatus();
    }, 5_000);

    return () => clearInterval(interval);
  }, [refreshStatus]);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Tamper Monitor</Text>
      <Text style={styles.subtitle}>
        Live Frida, debugger, and hook detection via native polling. Tamper
        checks stay off until you enable them (avoids IDE debugger noise in
        __DEV__).
      </Text>

      {loading ? <ActivityIndicator size="large" color="#38bdf8" /> : null}
      {error ? <Text style={styles.error}>{error}</Text> : null}

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Tamper checks</Text>
        <Text style={styles.row}>
          Enabled:{' '}
          <Text style={styles.value}>{tamperEnabled ? 'Yes' : 'No'}</Text>
        </Text>
        {!tamperEnabled ? (
          <Pressable style={styles.button} onPress={enableTamperMonitoring}>
            <Text style={styles.buttonText}>Enable tamper monitoring</Text>
          </Pressable>
        ) : (
          <Text style={styles.instruction}>
            Monitoring is active. Attach a debugger or Frida on a test device to
            see events below.
          </Text>
        )}
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Listener</Text>
        <Text style={styles.row}>
          Status:{' '}
          <Text style={styles.value}>{listening ? 'Listening' : 'Off'}</Text>
        </Text>
        <Text style={styles.row}>
          Events received:{' '}
          <Text style={styles.value}>{liveThreats.length}</Text>
        </Text>
        {status ? (
          <>
            <Text style={styles.row}>
              Native monitoring:{' '}
              <Text style={styles.value}>
                {status.monitoring ? 'Active' : 'Off'}
              </Text>
            </Text>
            <Text style={styles.row}>
              Last poll:{' '}
              <Text style={styles.value}>
                {status.lastPollAt != null
                  ? formatTimestamp(status.lastPollAt)
                  : '—'}
              </Text>
            </Text>
          </>
        ) : null}
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>How to test safely</Text>
        <Text style={styles.instruction}>
          1. Tap “Enable tamper monitoring” above (keeps launch quiet under
          Android Studio / Xcode).
        </Text>
        <Text style={styles.instruction}>
          2. Android: Debug from the IDE — debugger / TracerPid should fire
          while attached.
        </Text>
        <Text style={styles.instruction}>
          3. iOS device: attach Xcode debugger, or use Frida/Objection on a test
          device. Simulator skips debugger and several jailbreak probes to
          reduce false positives.
        </Text>
        <Text style={styles.instruction}>
          4. Detach the debugger — new events stop once signals clear.
        </Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>
          Live threat stream ({liveThreats.length})
        </Text>
        {liveThreats.length === 0 ? (
          <Text style={styles.empty}>Waiting for native threat events…</Text>
        ) : (
          liveThreats.map((threat, index) => (
            <View
              key={`${threat.type}-${threat.timestamp}-${index}`}
              style={styles.threatRow}
            >
              <Text style={styles.threatMeta}>
                {formatTimestamp(threat.timestamp)} · {threat.platform}
              </Text>
              <Text
                style={[
                  styles.threatType,
                  { color: severityColor(threat.severity) },
                ]}
              >
                {threat.type} · {threat.severity}
              </Text>
              <Text style={styles.threatMessage}>{threat.message}</Text>
            </View>
          ))
        )}
      </View>

      <Pressable
        style={styles.buttonSecondary}
        onPress={() => setLiveThreats([])}
      >
        <Text style={styles.buttonSecondaryText}>Clear events</Text>
      </Pressable>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: {
    flexGrow: 1,
    padding: 24,
    gap: 16,
    backgroundColor: '#0f172a',
  },
  title: {
    fontSize: 28,
    fontWeight: '700',
    color: '#f8fafc',
  },
  subtitle: {
    fontSize: 14,
    color: '#94a3b8',
    marginBottom: 8,
  },
  card: {
    backgroundColor: '#1e293b',
    borderRadius: 12,
    padding: 16,
    gap: 8,
  },
  cardTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#e2e8f0',
    marginBottom: 4,
  },
  row: {
    color: '#94a3b8',
    fontSize: 14,
  },
  value: {
    color: '#e2e8f0',
    fontWeight: '500',
  },
  instruction: {
    color: '#cbd5e1',
    fontSize: 14,
    lineHeight: 20,
  },
  threatRow: {
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#334155',
    paddingTop: 8,
    gap: 4,
  },
  threatMeta: {
    color: '#64748b',
    fontSize: 11,
  },
  threatType: {
    fontWeight: '600',
    textTransform: 'uppercase',
    fontSize: 12,
  },
  threatMessage: {
    color: '#cbd5e1',
    fontSize: 14,
  },
  empty: {
    color: '#64748b',
    fontSize: 14,
    fontStyle: 'italic',
  },
  buttonSecondary: {
    backgroundColor: '#334155',
    borderRadius: 10,
    paddingVertical: 14,
    alignItems: 'center',
  },
  buttonSecondaryText: {
    color: '#e2e8f0',
    fontWeight: '600',
    fontSize: 16,
  },
  button: {
    backgroundColor: '#2563eb',
    borderRadius: 10,
    paddingVertical: 14,
    alignItems: 'center',
    marginTop: 8,
  },
  buttonText: {
    color: '#ffffff',
    fontWeight: '600',
    fontSize: 16,
  },
  error: {
    color: '#f87171',
    fontSize: 14,
  },
});
