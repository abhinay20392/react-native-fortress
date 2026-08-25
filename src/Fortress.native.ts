import { NativeEventEmitter } from 'react-native';
import NativeFortress from './NativeFortress';
import type {
  FortressConfig,
  FortressStatus,
  FortressSubscription,
  PinnedFetchResult,
  SslPinConfig,
  ThreatEvent,
} from './types';

const THREAT_EVENT = 'onFortressThreat';
const fortressEmitter = new NativeEventEmitter(NativeFortress);

function parseThreat(raw: Object): ThreatEvent {
  const threat = raw as ThreatEvent;
  return {
    type: threat.type,
    severity: threat.severity,
    message: threat.message,
    platform: threat.platform,
    timestamp: threat.timestamp,
  };
}

function parseThreats(raw: Object[]): ThreatEvent[] {
  return raw.map(parseThreat);
}

export const Fortress = {
  configure(config: FortressConfig): Promise<void> {
    return NativeFortress.configure(config);
  },

  startMonitoring(): Promise<void> {
    return NativeFortress.startMonitoring();
  },

  stopMonitoring(): Promise<void> {
    return NativeFortress.stopMonitoring();
  },

  async runChecks(): Promise<ThreatEvent[]> {
    const result = await NativeFortress.runChecks();
    return parseThreats(result);
  },

  isDeviceCompromised(): Promise<boolean> {
    return NativeFortress.isDeviceCompromised();
  },

  configureSslPinning(pins: SslPinConfig[]): Promise<void> {
    return NativeFortress.configureSslPinning(pins);
  },

  async fetchPinned(url: string): Promise<PinnedFetchResult> {
    const result = await NativeFortress.performPinnedRequest(url);
    return result as PinnedFetchResult;
  },

  async getStatus(): Promise<FortressStatus> {
    const status = await NativeFortress.getStatus();
    return status as FortressStatus;
  },

  showBlockOverlay(message?: string): Promise<void> {
    return NativeFortress.showBlockOverlay(
      message ?? 'Security threat detected (demo).'
    );
  },

  addThreatListener(
    callback: (event: ThreatEvent) => void
  ): FortressSubscription {
    const subscription = fortressEmitter.addListener(THREAT_EVENT, (event) => {
      callback(parseThreat(event as Object));
    });

    return {
      remove: () => subscription.remove(),
    };
  },
};
