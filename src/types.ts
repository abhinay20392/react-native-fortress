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

/** Severity floor for `exit` / `block_ui` enforcement. */
export type ExitOnSeverity = 'high' | 'critical';

/** Runtime posture — soft defaults for noisy checks / policies. */
export type FortressMode = 'dev' | 'prod';

export type PinnedHttpMethod =
  | 'GET'
  | 'POST'
  | 'PUT'
  | 'PATCH'
  | 'DELETE'
  | 'HEAD';

export interface ThreatEvent {
  type: ThreatType;
  severity: ThreatSeverity;
  message: string;
  platform: ThreatPlatform;
  timestamp: number;
  /** Stable machine-readable code, e.g. `ROOT_SU_BINARY`. */
  code?: string;
  /** Detector that produced the signal, e.g. `RootDetector`. */
  detector?: string;
  /** Optional structured details for logging / server attestation. */
  evidence?: Record<string, string | number | boolean | string[]>;
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

/**
 * Threat tuning applied after detectors run, before scoring / emit / policy.
 */
export interface FortressThreatTuning {
  /**
   * Override detector severity by threat type.
   * Example: `{ debugger: 'medium' }` in staging.
   */
  severityOverrides?: Partial<Record<ThreatType, ThreatSeverity>>;
  /**
   * Threat types to drop entirely (internal builds, known-safe MDM ROMs, etc.).
   */
  allowlist?: ThreatType[];
  /**
   * When true (default), monitoring only re-emits JS events when the threat set changes.
   * Policy (`exit` / `block_ui`) still runs every poll when thresholds are met.
   */
  dedupeEvents?: boolean;
}

export interface FortressConfig {
  /**
   * Soft posture for defaults.
   * - `dev` — if `checks.tamper` omitted, defaults to `false` (avoids IDE debugger noise)
   * - `prod` — if `checks.tamper` omitted, defaults to `true`
   */
  mode?: FortressMode;
  /** Start continuous monitoring when configured */
  monitor?: boolean;
  /** Native poll interval in milliseconds */
  pollIntervalMs?: number;
  /** Enable or disable individual check categories */
  checks?: FortressChecksConfig;
  /**
   * Response policy when a threat at or above `exitOn` is detected.
   * - `log` — log + emit events (default)
   * - `exit` — terminate the process
   * - `block_ui` — native full-screen overlay (non-dismissible; does not rely on JS)
   */
  onCriticalThreat?: CriticalThreatAction;
  /**
   * Minimum severity that triggers `exit` / `block_ui`.
   * Default: `'high'` (v1 parity — high **or** critical).
   * Set `'critical'` to only enforce on critical threats.
   */
  exitOn?: ExitOnSeverity;
  /**
   * Shared native/C++ compromise thresholds.
   * JS never decides compromise — native detectors feed C++ scoring.
   */
  scoring?: FortressScoringConfig;
  /** Post-detector severity overrides, allowlists, and emit dedupe. */
  threatTuning?: FortressThreatTuning;
  /**
   * SHA-256 hex digest of your release signing certificate (Android only).
   * **Required** when `checks.repackaging` is `true` (configure rejects otherwise).
   */
  expectedSigningCertificateSha256?: string;
}

export interface SslPinConfig {
  host: string;
  publicKeyHashes: string[];
  includeSubdomains?: boolean;
}

export interface SslPinHostStatus {
  host: string;
  pinCount: number;
  includeSubdomains: boolean;
}

/**
 * Stable `reason` values on SSL-related rejections (`error.userInfo.reason` / native map).
 */
export type SslPinFailureReason =
  | 'not_configured'
  | 'invalid_url'
  | 'unsupported_method'
  | 'pin_mismatch'
  | 'network';

export interface SslPinningStatus {
  configured: boolean;
  hosts: SslPinHostStatus[];
  /**
   * Android: `true` when OkHttp factory is installed (RN `fetch` is covered).
   * iOS: always `false` — only `fetchPinned` is pinned.
   */
  coversGlobalFetch: boolean;
  /** Android-only: whether Fortress re-asserted the OkHttp factory. */
  okHttpFactoryInstalled?: boolean;
  platformNote: string;
}

export interface PinnedFetchRequest {
  url: string;
  method?: PinnedHttpMethod;
  headers?: Record<string, string>;
  /** Request body (string). Ignored for GET/HEAD. */
  body?: string;
}

export interface FortressStatus {
  monitoring: boolean;
  configured: boolean;
  platform: ThreatPlatform;
  version: string;
  mode?: FortressMode;
  pollIntervalMs?: number;
  /** Unix ms timestamp of the last native background poll */
  lastPollAt?: number;
  /** Threat count from the last native background poll */
  lastThreatCount?: number;
  /** Whether native SSL pinning has been configured */
  sslPinningConfigured?: boolean;
  /** Effective `exitOn` threshold */
  exitOn?: ExitOnSeverity;
}

export interface PinnedFetchResult {
  ok: boolean;
  status: number;
  url: string;
  body: string;
  pinned: boolean;
  sslPinVerified: boolean;
  method?: PinnedHttpMethod;
}

export interface FortressSubscription {
  remove(): void;
}
