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
  /**
   * Emulator / Simulator detection. Opt-in (default off).
   * Severity is medium — alone it does not mark the device compromised.
   */
  emulator?: boolean;
  /** Android only — requires `expectedSigningCertificateSha256` in config */
  repackaging?: boolean;
}

/**
 * Shared C++ scoring policy (Android + iOS). Defaults preserve v1.x behavior.
 */
export interface FortressScoringConfig {
  /**
   * Any single threat at or above this severity → compromised.
   * Default: `'high'`.
   */
  aloneAt?: ThreatSeverity;
  /**
   * Count threats at or above this severity toward aggregate compromise.
   * Default: `'low'` (any 2+ threats). Set to `'medium'` for “N medium signals”.
   */
  countAtOrAbove?: ThreatSeverity;
  /** Aggregate count threshold. Default: `2`. */
  countThreshold?: number;
}

export interface FortressConfig {
  /** Start continuous monitoring when configured */
  monitor?: boolean;
  /** Native poll interval in milliseconds */
  pollIntervalMs?: number;
  /** Enable or disable individual check categories */
  checks?: FortressChecksConfig;
  /**
   * Response policy when a **high or critical** threat is detected during monitoring.
   * - `log` — log + emit events (default)
   * - `exit` — terminate the process (triggers on high **or** critical in v1.x)
   * - `block_ui` — native full-screen overlay (non-dismissible; does not rely on JS)
   */
  onCriticalThreat?: CriticalThreatAction;
  /**
   * Shared native/C++ compromise thresholds.
   * JS never decides compromise — native detectors feed C++ scoring.
   */
  scoring?: FortressScoringConfig;
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
