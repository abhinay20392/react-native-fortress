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
        await Fortress.configure({
          monitor: true,
          pollIntervalMs: 10_000,
          checks: {
            tamper: true,
            root: false,
            jailbreak: false,
          },
          onCriticalThreat: 'log',
        });
        await Fortress.startMonitoring();
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
        Phase 3 — live Frida, debugger, and hook detection via native polling
      </Text>

      {loading ? <ActivityIndicator size="large" color="#38bdf8" /> : null}
      {error ? <Text style={styles.error}>{error}</Text> : null}

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
          Android: run the app via Android Studio with the debugger attached, or
          use "Debug" from the IDE. Debugger and TracerPid checks should fire
          while attached.
        </Text>
        <Text style={styles.instruction}>
          iOS: attach Xcode debugger (Debug → Attach to Process).
          Frida/Objection on a test device should trigger frida/hooking signals.
        </Text>
        <Text style={styles.instruction}>
          Detach the debugger and pull to refresh status — events stream in
          while monitoring is active.
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
  error: {
    color: '#f87171',
    fontSize: 14,
  },
});
