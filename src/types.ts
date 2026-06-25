export type ThreatType =
  | 'frida'
  | 'debugger'
  | 'hooking'
  | 'root'
  | 'jailbreak'
  | 'ssl_pin_failure'
  | 'emulator'
  | 'repackaging';

export type ThreatSeverity = 'low' | 'medium' | 'high' | 'critical';

export type ThreatPlatform = 'ios' | 'android';

export type CriticalThreatAction = 'log' | 'block_ui' | 'exit';

export interface ThreatEvent {
  type: ThreatType;
  severity: ThreatSeverity;
  message: string;
  platform: ThreatPlatform;
  timestamp: number;
}

export interface FortressChecksConfig {
  tamper?: boolean;
  root?: boolean;
  jailbreak?: boolean;
  sslPinning?: boolean;
  emulator?: boolean;
  /** Android only — requires `expectedSigningCertificateSha256` in config */
  repackaging?: boolean;
}

export interface FortressConfig {
  /** Start continuous monitoring when configured */
  monitor?: boolean;
  /** Native poll interval in milliseconds */
  pollIntervalMs?: number;
  /** Enable or disable individual check categories */
  checks?: FortressChecksConfig;
  /** Response policy for critical threats */
  onCriticalThreat?: CriticalThreatAction;
  /**
   * SHA-256 hex digest of your release signing certificate (Android only).
   * Required when `checks.repackaging` is enabled.
   */
  expectedSigningCertificateSha256?: string;
}

export interface SslPinConfig {
  host: string;
  publicKeyHashes: string[];
  includeSubdomains?: boolean;
}

export interface FortressStatus {
  monitoring: boolean;
  configured: boolean;
  platform: ThreatPlatform;
  version: string;
  pollIntervalMs?: number;
  /** Unix ms timestamp of the last native background poll */
  lastPollAt?: number;
  /** Threat count from the last native background poll */
  lastThreatCount?: number;
  /** Whether native SSL pinning has been configured */
  sslPinningConfigured?: boolean;
}

export interface PinnedFetchResult {
  ok: boolean;
  status: number;
  url: string;
  body: string;
  pinned: boolean;
  sslPinVerified: boolean;
}

export interface FortressSubscription {
  remove(): void;
}
