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

function formatTimestamp(ms?: number): string {
  if (ms == null) {
    return '—';
  }

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

export function DeviceIntegrityScreen() {
  const [status, setStatus] = useState<FortressStatus | null>(null);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [compromised, setCompromised] = useState<boolean | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const runChecks = useCallback(async () => {
    setLoading(true);
    setError(null);

    try {
      const [nextStatus, nextThreats, nextCompromised] = await Promise.all([
        Fortress.getStatus(),
        Fortress.runChecks(),
        Fortress.isDeviceCompromised(),
      ]);

      setStatus(nextStatus);
      setThreats(nextThreats);
      setCompromised(nextCompromised);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const bootstrap = async () => {
      try {
        // __DEV__: tamper off by default so IDE debuggers do not trip integrity demos.
        await configureExampleFortress({
          pollIntervalMs: 15_000,
          checks: {
            root: true,
            jailbreak: true,
            tamper: false,
          },
        });
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to configure Fortress'
        );
      }

      await runChecks();
    };

    bootstrap();
  }, [runChecks]);

  useEffect(() => {
    const interval = setInterval(() => {
      Fortress.getStatus()
        .then(setStatus)
        .catch(() => undefined);
    }, 5_000);

    return () => clearInterval(interval);
  }, []);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>Device Integrity</Text>
      <Text style={styles.subtitle}>
        Native root / jailbreak checks. Emulator detection is on in the example
        (medium severity). Tamper stays off here (see Tamper tab). On iOS
        Simulator, some jailbreak probes are skipped to avoid host false
        positives.
      </Text>

      {loading ? <ActivityIndicator size="large" color="#38bdf8" /> : null}
      {error ? <Text style={styles.error}>{error}</Text> : null}

      {status ? (
        <View style={styles.card}>
          <Text style={styles.cardTitle}>Monitoring</Text>
          <Text style={styles.row}>
            Platform: <Text style={styles.value}>{status.platform}</Text>
          </Text>
          <Text style={styles.row}>
            Monitoring:{' '}
            <Text style={styles.value}>
              {status.monitoring ? 'Active' : 'Off'}
            </Text>
          </Text>
          <Text style={styles.row}>
            Poll interval:{' '}
            <Text style={styles.value}>
              {status.pollIntervalMs != null
                ? `${status.pollIntervalMs / 1000}s`
                : '—'}
            </Text>
          </Text>
          <Text style={styles.row}>
            Last native poll:{' '}
            <Text style={styles.value}>
              {formatTimestamp(status.lastPollAt)}
            </Text>
          </Text>
          <Text style={styles.row}>
            Last poll threats:{' '}
            <Text style={styles.value}>{status.lastThreatCount ?? 0}</Text>
          </Text>
        </View>
      ) : null}

      <View
        style={[styles.card, compromised ? styles.cardDanger : styles.cardSafe]}
      >
        <Text style={styles.cardTitle}>Compromised?</Text>
        <Text style={styles.compromisedValue}>
          {compromised === null ? '—' : compromised ? 'YES' : 'No'}
        </Text>
        <Text style={styles.hint}>
          {compromised
            ? 'One or more integrity signals exceeded the threshold.'
            : 'No integrity threats detected (or only a single low-severity signal).'}
        </Text>
      </View>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>
          On-demand checks ({threats.length} signal
          {threats.length === 1 ? '' : 's'})
        </Text>
        {threats.length === 0 ? (
          <Text style={styles.empty}>No threats detected</Text>
        ) : (
          threats.map((threat, index) => (
            <View key={`${threat.type}-${index}`} style={styles.threatRow}>
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

      <Pressable style={styles.button} onPress={() => runChecks()}>
        <Text style={styles.buttonText}>Run checks again</Text>
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
  cardSafe: {
    borderWidth: 1,
    borderColor: '#166534',
  },
  cardDanger: {
    borderWidth: 1,
    borderColor: '#b91c1c',
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
  compromisedValue: {
    fontSize: 24,
    fontWeight: '700',
    color: '#f8fafc',
  },
  hint: {
    color: '#94a3b8',
    fontSize: 13,
  },
  threatRow: {
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#334155',
    paddingTop: 8,
    gap: 4,
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
  button: {
    backgroundColor: '#2563eb',
    borderRadius: 10,
    paddingVertical: 14,
    alignItems: 'center',
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
