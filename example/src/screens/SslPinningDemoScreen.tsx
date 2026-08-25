import {
  useCallback,
  useEffect,
  useState,
  type Dispatch,
  type SetStateAction,
} from 'react';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { Fortress } from 'react-native-fortress';
import type { PinnedFetchResult, ThreatEvent } from 'react-native-fortress';

const DEMO_HOST = 'jsonplaceholder.typicode.com';
const DEMO_URL = `https://${DEMO_HOST}/todos/1`;
const VALID_PIN = '3U84jdV3AKjdpmiBjrwT1shpZS0fQDhoLspJ7Exj1AU=';
const INVALID_PIN = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

type RequestState = {
  label: string;
  loading: boolean;
  success: boolean | null;
  message: string;
};

const initialRequestState = (label: string): RequestState => ({
  label,
  loading: false,
  success: null,
  message: 'Not run yet',
});

export function SslPinningDemoScreen() {
  const [ready, setReady] = useState(false);
  const [pinStatusNote, setPinStatusNote] = useState('');
  const [sslEvents, setSslEvents] = useState<ThreatEvent[]>([]);
  const [unpinned, setUnpinned] = useState<RequestState>(
    initialRequestState('Unpinned fetch()')
  );
  const [pinnedOk, setPinnedOk] = useState<RequestState>(
    initialRequestState('fetchPinned (valid pin)')
  );
  const [pinnedBad, setPinnedBad] = useState<RequestState>(
    initialRequestState('fetchPinned (wrong pin)')
  );

  useEffect(() => {
    const subscription = Fortress.addThreatListener((event) => {
      if (event.type === 'ssl_pin_failure') {
        setSslEvents((current) => [event, ...current].slice(0, 10));
      }
    });

    return () => subscription.remove();
  }, []);

  const configurePins = useCallback(async (hashes: string[]) => {
    await Fortress.configureSslPinning([
      {
        host: DEMO_HOST,
        publicKeyHashes: hashes,
      },
    ]);
    const status = await Fortress.getSslPinningStatus();
    setPinStatusNote(
      `${status.hosts.map((h) => `${h.host}×${h.pinCount}`).join(', ')} — ${
        status.coversGlobalFetch
          ? 'global fetch covered (Android OkHttp)'
          : 'use fetchPinned only (iOS)'
      }`
    );
    setReady(true);
  }, []);

  const runUnpinnedFetch = useCallback(async () => {
    setUnpinned((state) => ({ ...state, loading: true, message: 'Running…' }));

    try {
      const response = await fetch(DEMO_URL);
      const body = await response.text();
      setUnpinned({
        label: 'Unpinned fetch()',
        loading: false,
        success: response.ok,
        message: `HTTP ${response.status} — ${body.slice(0, 80)}…`,
      });
    } catch (error) {
      setUnpinned({
        label: 'Unpinned fetch()',
        loading: false,
        success: false,
        message: error instanceof Error ? error.message : 'Request failed',
      });
    }
  }, []);

  const runPinnedFetch = useCallback(
    async (
      hashes: string[],
      setState: Dispatch<SetStateAction<RequestState>>,
      label: string
    ) => {
      setState((state) => ({ ...state, loading: true, message: 'Running…' }));

      try {
        await configurePins(hashes);
        const result: PinnedFetchResult = await Fortress.fetchPinned(DEMO_URL);
        setState({
          label,
          loading: false,
          success: result.ok,
          message: `HTTP ${result.status} — ${result.body.slice(0, 80)}…`,
        });
      } catch (error) {
        const nativeError = error as {
          message?: string;
          code?: string;
          userInfo?: { reason?: string };
        };
        const message =
          nativeError.message ??
          (error instanceof Error ? error.message : 'Pinned request failed');
        const reason = nativeError.userInfo?.reason ?? nativeError.code;
        setState({
          label,
          loading: false,
          success: false,
          message: `${reason ? `[${reason}] ` : ''}${message}`,
        });
      }
    },
    [configurePins]
  );

  useEffect(() => {
    configurePins([VALID_PIN]).catch(() => undefined);
  }, [configurePins]);

  return (
    <ScrollView contentContainerStyle={styles.container}>
      <Text style={styles.title}>SSL Pinning</Text>
      <Text style={styles.subtitle}>
        Phase 4 — native SPKI pinning via OkHttp (Android) and NSURLSession
        delegate (iOS)
      </Text>

      <View style={styles.card}>
        <Text style={styles.cardTitle}>Configuration</Text>
        <Text style={styles.row}>Host: {DEMO_HOST}</Text>
        <Text style={styles.row}>Valid SPKI: {VALID_PIN}</Text>
        <Text style={styles.row}>
          Pinning configured: {ready ? 'Yes' : 'No'}
        </Text>
        {pinStatusNote ? (
          <Text style={styles.row}>Status: {pinStatusNote}</Text>
        ) : null}
      </View>

      <RequestCard
        state={unpinned}
        onRun={runUnpinnedFetch}
        hint="Uses JS fetch() — not pinned by Fortress."
      />

      <RequestCard
        state={pinnedOk}
        onRun={() => runPinnedFetch([VALID_PIN], setPinnedOk, pinnedOk.label)}
        hint="Uses Fortress.fetchPinned() with the correct SPKI hash."
      />

      <RequestCard
        state={pinnedBad}
        onRun={() =>
          runPinnedFetch([INVALID_PIN], setPinnedBad, pinnedBad.label)
        }
        hint="Uses Fortress.fetchPinned() with a deliberately wrong pin."
      />

      <View style={styles.card}>
        <Text style={styles.cardTitle}>
          ssl_pin_failure events ({sslEvents.length})
        </Text>
        {sslEvents.length === 0 ? (
          <Text style={styles.empty}>No SSL pin failures yet</Text>
        ) : (
          sslEvents.map((event, index) => (
            <View key={`${event.timestamp}-${index}`} style={styles.eventRow}>
              <Text style={styles.eventMessage}>{event.message}</Text>
            </View>
          ))
        )}
      </View>
    </ScrollView>
  );
}

function RequestCard({
  state,
  onRun,
  hint,
}: {
  state: RequestState;
  onRun: () => void;
  hint: string;
}) {
  return (
    <View style={styles.card}>
      <Text style={styles.cardTitle}>{state.label}</Text>
      <Text style={styles.hint}>{hint}</Text>
      <Text
        style={[
          styles.result,
          state.success === true && styles.resultOk,
          state.success === false && styles.resultError,
        ]}
      >
        {state.message}
      </Text>
      <Pressable style={styles.button} onPress={onRun} disabled={state.loading}>
        {state.loading ? (
          <ActivityIndicator color="#ffffff" />
        ) : (
          <Text style={styles.buttonText}>Run request</Text>
        )}
      </Pressable>
    </View>
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
  },
  row: {
    color: '#cbd5e1',
    fontSize: 13,
  },
  hint: {
    color: '#94a3b8',
    fontSize: 13,
  },
  result: {
    color: '#e2e8f0',
    fontSize: 14,
  },
  resultOk: {
    color: '#4ade80',
  },
  resultError: {
    color: '#f87171',
  },
  button: {
    backgroundColor: '#2563eb',
    borderRadius: 10,
    paddingVertical: 12,
    alignItems: 'center',
    marginTop: 4,
  },
  buttonText: {
    color: '#ffffff',
    fontWeight: '600',
  },
  empty: {
    color: '#64748b',
    fontStyle: 'italic',
  },
  eventRow: {
    borderTopWidth: StyleSheet.hairlineWidth,
    borderTopColor: '#334155',
    paddingTop: 8,
  },
  eventMessage: {
    color: '#fca5a5',
    fontSize: 13,
  },
});
