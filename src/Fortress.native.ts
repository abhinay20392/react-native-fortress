import { NativeEventEmitter } from 'react-native';
import NativeFortress from './NativeFortress';
import type {
  FortressConfig,
  FortressStatus,
  FortressSubscription,
  PinnedFetchRequest,
  PinnedFetchResult,
  SslPinConfig,
  SslPinningStatus,
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
    code: threat.code,
    detector: threat.detector,
    evidence: threat.evidence,
  };
}

function parseThreats(raw: Object[]): ThreatEvent[] {
  return raw.map(parseThreat);
}

function toPinnedOptions(
  request: string | PinnedFetchRequest
): PinnedFetchRequest {
  if (typeof request === 'string') {
    return { url: request, method: 'GET' };
  }
  return {
    url: request.url,
    method: request.method ?? 'GET',
    headers: request.headers,
    body: request.body,
  };
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

  getThreatConfidence(): Promise<number> {
    return NativeFortress.getThreatConfidence();
  },

  configureSslPinning(pins: SslPinConfig[]): Promise<void> {
    return NativeFortress.configureSslPinning(pins);
  },

  /**
   * Perform a pinned HTTP request.
   * Accepts a URL string (GET) or `{ url, method?, headers?, body? }`.
   */
  async fetchPinned(
    request: string | PinnedFetchRequest
  ): Promise<PinnedFetchResult> {
    const result = await NativeFortress.performPinnedRequest(
      toPinnedOptions(request)
    );
    return result as PinnedFetchResult;
  },

  async getSslPinningStatus(): Promise<SslPinningStatus> {
    const status = await NativeFortress.getSslPinningStatus();
    return status as SslPinningStatus;
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
