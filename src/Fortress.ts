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

const STUB_THREATS: ThreatEvent[] = [
  {
    type: 'root',
    severity: 'low',
    message: 'Stub: no threats detected (JS fallback)',
    platform: 'android',
    timestamp: Date.now(),
    code: 'STUB_OK',
    detector: 'StubDetector',
  },
];

let configured = false;
let monitoring = false;
let sslPinningConfigured = false;
let mode: 'dev' | 'prod' | undefined;
let exitOn: 'high' | 'critical' = 'high';
const listeners = new Set<(event: ThreatEvent) => void>();

function assertRepackagingConfig(config: FortressConfig): void {
  if (config.checks?.repackaging === true) {
    const hash = config.expectedSigningCertificateSha256?.trim();
    if (!hash) {
      throw new Error(
        'E_CONFIG: checks.repackaging is true but expectedSigningCertificateSha256 is missing'
      );
    }
  }
}

/**
 * Non-native fallback used by Metro on unsupported platforms and in unit tests.
 * Native apps resolve `Fortress.native.ts` instead.
 */
export const Fortress = {
  async configure(config: FortressConfig): Promise<void> {
    assertRepackagingConfig(config);
    configured = true;
    mode = config.mode;
    exitOn = config.exitOn === 'critical' ? 'critical' : 'high';
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

  async getThreatConfidence(): Promise<number> {
    return 0;
  },

  async configureSslPinning(_pins: SslPinConfig[]): Promise<void> {
    sslPinningConfigured = _pins.length > 0;
  },

  async fetchPinned(
    request: string | PinnedFetchRequest
  ): Promise<PinnedFetchResult> {
    const options =
      typeof request === 'string'
        ? { url: request, method: 'GET' as const }
        : request;
    return {
      ok: true,
      status: 200,
      url: options.url,
      body: '{"stub":true}',
      pinned: true,
      sslPinVerified: true,
      method: options.method ?? 'GET',
    };
  },

  async getSslPinningStatus(): Promise<SslPinningStatus> {
    return {
      configured: sslPinningConfigured,
      hosts: sslPinningConfigured
        ? [{ host: 'example.com', pinCount: 1, includeSubdomains: false }]
        : [],
      coversGlobalFetch: false,
      platformNote: 'Stub platform — no native SSL pinning.',
    };
  },

  async getStatus(): Promise<FortressStatus> {
    return {
      monitoring,
      configured,
      sslPinningConfigured,
      platform: 'android',
      version: '2.0.0',
      mode,
      exitOn,
    };
  },

  async showBlockOverlay(_message?: string): Promise<void> {
    // Stub — native platforms show the real overlay.
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
