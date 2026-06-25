import type {
  FortressConfig,
  FortressStatus,
  FortressSubscription,
  PinnedFetchResult,
  SslPinConfig,
  ThreatEvent,
} from './types';

const STUB_THREATS: ThreatEvent[] = [
  {
    type: 'root',
    severity: 'low',
    message: 'Stub: no threats detected (JS fallback)',
    platform: 'android',
    timestamp: Date.now(),
  },
];

let configured = false;
let monitoring = false;
let sslPinningConfigured = false;
const listeners = new Set<(event: ThreatEvent) => void>();

/**
 * Non-native fallback used by Metro on unsupported platforms and in unit tests.
 * Native apps resolve `Fortress.native.ts` instead.
 */
export const Fortress = {
  async configure(config: FortressConfig): Promise<void> {
    configured = true;
    if (config.monitor) {
      monitoring = true;
    }
  },

  async startMonitoring(): Promise<void> {
    monitoring = true;
  },

  async stopMonitoring(): Promise<void> {
    monitoring = false;
  },

  async runChecks(): Promise<ThreatEvent[]> {
    return STUB_THREATS.map((threat) => ({
      ...threat,
      timestamp: Date.now(),
    }));
  },

  async isDeviceCompromised(): Promise<boolean> {
    return false;
  },

  async configureSslPinning(_pins: SslPinConfig[]): Promise<void> {
    sslPinningConfigured = _pins.length > 0;
  },

  async fetchPinned(url: string): Promise<PinnedFetchResult> {
    return {
      ok: true,
      status: 200,
      url,
      body: '{"stub":true}',
      pinned: true,
      sslPinVerified: true,
    };
  },

  async getStatus(): Promise<FortressStatus> {
    return {
      monitoring,
      configured,
      sslPinningConfigured,
      platform: 'android',
      version: '1.0.0',
    };
  },

  addThreatListener(
    callback: (event: ThreatEvent) => void
  ): FortressSubscription {
    listeners.add(callback);
    return {
      remove: () => {
        listeners.delete(callback);
      },
    };
  },
};
