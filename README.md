# react-native-fortress

Native-first mobile security for React Native: root/jailbreak detection, anti-tampering (Frida, debugger, hooks), SSL pinning, shared C++ threat scoring, and configurable response policy.

**Current version: 2.0.0** — see [MIGRATION_v2.md](./MIGRATION_v2.md) if upgrading from 1.x, and [CHANGELOG.md](./CHANGELOG.md) for the full list of changes.

## Install

```sh
npm install react-native-fortress
# or
yarn add react-native-fortress
```

**iOS** — run `pod install` in your `ios/` directory after installing (required for native + C++ sources).

Requires React Native **0.73+**. Autolinking handles native setup. New Architecture / Turbo Modules are supported.

## Quick start

Call `Fortress.configure()` early (before sensitive screens or network calls):

```typescript
import { Fortress } from 'react-native-fortress';

await Fortress.configure({
  mode: __DEV__ ? 'dev' : 'prod',
  monitor: true,
  pollIntervalMs: 30_000,
  checks: {
    tamper: true,
    root: true, // Android
    jailbreak: true, // iOS
    emulator: false,
    repackaging: false,
  },
  onCriticalThreat: 'log', // prefer 'log' until you need hard fail
  exitOn: 'high',
});

const compromised = await Fortress.isDeviceCompromised();
const confidence = await Fortress.getThreatConfidence(); // 0–100
const threats = await Fortress.runChecks();
const status = await Fortress.getStatus();
```

## API reference

| Method | Description |
|--------|-------------|
| `configure(config)` | Enable checks, scoring, tuning, monitoring, and response policy |
| `startMonitoring()` / `stopMonitoring()` | Control native background polling |
| `runChecks()` | Run enabled checks on demand → `ThreatEvent[]` (also applies policy) |
| `isDeviceCompromised()` | `true` when shared **C++ scoring** marks the device compromised |
| `getThreatConfidence()` | 0–100 confidence for the current **tuned** threat set |
| `getStatus()` | Monitoring, platform, version, `mode`, `exitOn`, last poll stats |
| `configureSslPinning(pins)` | Set SPKI pins per host |
| `fetchPinned(url \| options)` | Pinned HTTP (`GET` by default; method/headers/body supported) |
| `getSslPinningStatus()` | Configured hosts, pin counts, whether global `fetch` is covered |
| `showBlockOverlay(message?)` | Force-show the native `block_ui` overlay (demos / custom policy) |
| `addThreatListener(cb)` | Subscribe to live `onFortressThreat` events |

### `configure` options

```typescript
await Fortress.configure({
  mode: __DEV__ ? 'dev' : 'prod',
  monitor: true,
  pollIntervalMs: 30_000,

  checks: {
    tamper: true, // Frida, debugger, hooks
    root: true, // Android
    jailbreak: true, // iOS
    emulator: false, // opt-in; medium severity (alone ≠ compromised)
    repackaging: false, // Android — requires expectedSigningCertificateSha256
  },

  onCriticalThreat: 'log', // 'log' | 'block_ui' | 'exit'
  exitOn: 'high', // 'high' | 'critical'

  scoring: {
    aloneAt: 'high',
    countAtOrAbove: 'low',
    countThreshold: 2,
  },

  threatTuning: {
    severityOverrides: { debugger: 'medium' },
    allowlist: [], // e.g. ['emulator']
    dedupeEvents: true,
  },

  expectedSigningCertificateSha256: '...', // required when repackaging is true
});
```

| Option | Default | Notes |
|--------|---------|--------|
| `mode` | omitted | Soft-defaults `checks.tamper` when tamper is not set (`dev`→false, `prod`→true) |
| `monitor` | `false` | Start background polling after configure |
| `pollIntervalMs` | `30000` | Minimum `5000` |
| `onCriticalThreat` | `'log'` | Response when severity ≥ `exitOn` |
| `exitOn` | `'high'` | Floor for `exit` / `block_ui` |
| `scoring` | see below | Shared C++ compromise policy |
| `threatTuning` | see below | Allowlist / severity overrides / emit dedupe |
| `expectedSigningCertificateSha256` | — | **Required** if `checks.repackaging: true` |

### Threat events

```typescript
const subscription = Fortress.addThreatListener((event) => {
  console.warn(event.type, event.severity, event.code, event.message);
});
subscription.remove();
```

```typescript
{
  type: 'frida' | 'debugger' | 'hooking' | 'root' | 'jailbreak'
      | 'ssl_pin_failure' | 'emulator' | 'repackaging';
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  platform: 'ios' | 'android';
  timestamp: number;
  code?: string;     // e.g. SSL_PIN_FAILURE, EMULATOR_DETECTED
  detector?: string; // e.g. SslPinningManager, JailbreakDetector
  evidence?: Record<string, string | number | boolean | string[]>;
}
```

## Scoring (shared C++)

Compromise is decided in **native C++** (`cpp/fortress_scoring.cpp`) on Android and iOS — not in JavaScript.

| Rule (defaults) | Result |
|-----------------|--------|
| Any threat ≥ `aloneAt` (`high`) | Compromised |
| Count of threats ≥ `countAtOrAbove` (`low`) ≥ `countThreshold` (`2`) | Compromised |

```typescript
await Fortress.configure({
  scoring: {
    aloneAt: 'high',
    countAtOrAbove: 'medium', // “N medium signals”
    countThreshold: 2,
  },
});

const compromised = await Fortress.isDeviceCompromised();
const confidence = await Fortress.getThreatConfidence(); // 0–100
```

## Threat tuning

Applied **after** detectors, **before** C++ scoring / emit / policy:

| Field | Purpose |
|-------|---------|
| `severityOverrides` | Remap severity by threat type (e.g. quieter `debugger` in staging) |
| `allowlist` | Drop threat types entirely (internal builds, emulator farms, MDM) |
| `dedupeEvents` | Default `true` — monitoring only re-emits JS events when the threat set changes. `exit` / `block_ui` still evaluate every poll. |

```typescript
await Fortress.configure({
  threatTuning: {
    severityOverrides: { debugger: 'medium' },
    allowlist: ['emulator'],
    dedupeEvents: true,
  },
});
```

## Response policy (`onCriticalThreat` + `exitOn`)

| `onCriticalThreat` | Behavior |
|--------------------|----------|
| `log` (default) | Log + emit events |
| `exit` | Kill the process when a threat ≥ `exitOn` is seen |
| `block_ui` | Native full-screen overlay (non-dismissible; does not rely on JS) |

`exitOn` defaults to `'high'` (high **or** critical). Use `'critical'` to enforce only on critical threats.

Policies run from **monitoring** polls and from `runChecks()`.

`block_ui` needs a visible activity/window (foreground). It cannot be dismissed in this release — force-quit to recover while testing.

```typescript
await Fortress.showBlockOverlay('Optional custom message');
```

## Emulator / Simulator detection

Opt-in via `checks.emulator: true` (default **off**). Emits one `emulator` threat at **medium** severity — alone it does **not** make `isDeviceCompromised()` true (with default scoring).

```typescript
await Fortress.configure({
  checks: { emulator: true },
});
```

- **Android:** Build props (`goldfish` / `ranchu` / sdk), QEMU/Genymotion files, related system props  
- **iOS:** `TARGET_OS_SIMULATOR`, `hw.machine` / `uname` indicators, `SIMULATOR_DEVICE_NAME`

## SSL pinning

Pin TLS with SPKI hashes (SHA-256, base64).

**iOS SPKI hashing supports:** EC P-256 / P-384 / P-521 and RSA-2048 / 3072 / 4096.  
**Android** uses OkHttp `CertificatePinner`.

```typescript
await Fortress.configureSslPinning([
  {
    host: 'api.example.com',
    publicKeyHashes: [
      'PRIMARY_SPKI_HASH_BASE64=',
      'BACKUP_SPKI_HASH_BASE64=', // ship before cert rotation
    ],
    includeSubdomains: true,
  },
]);

const pinStatus = await Fortress.getSslPinningStatus();
// { configured, hosts, coversGlobalFetch, platformNote, okHttpFactoryInstalled? }

await Fortress.fetchPinned('https://api.example.com/health');

await Fortress.fetchPinned({
  url: 'https://api.example.com/items',
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ name: 'demo' }),
});
```

Supported methods: `GET` | `POST` | `PUT` | `PATCH` | `DELETE` | `HEAD`.

**Extract a pin:**

```bash
echo | openssl s_client -servername api.example.com -connect api.example.com:443 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Hashes may include or omit the `sha256/` prefix (normalized either way).

### Platform coverage

| Platform | What is pinned |
|----------|----------------|
| **Android** | `fetchPinned` **and** RN `fetch()` / XHR while Fortress’s OkHttp factory stays installed (eager package install + re-assert). Other libs that replace `OkHttpClientProvider` can undo this — configure pins early and check `getSslPinningStatus()`. |
| **iOS** | **Only** `Fortress.fetchPinned`. Global `fetch()` / XHR are **not** intercepted. |

### Failures and rotation

| Situation | Code | `userInfo.reason` |
|-----------|------|-------------------|
| Wrong / outdated pin | `E_SSL_PIN_FAILURE` | `pin_mismatch` (+ `ssl_pin_failure` threat) |
| Pinning not configured | `E_SSL_PINNING` | `not_configured` |
| Bad URL / method | `E_SSL_REQUEST` | `invalid_url` / `unsupported_method` |
| Other network failure | `E_SSL_REQUEST` | `network` |

```typescript
try {
  await Fortress.fetchPinned({ url: 'https://api.example.com/health' });
} catch (error: any) {
  console.warn(error?.code, error?.userInfo?.reason, error?.message);
}
```

Ship a **backup** pin before rotating the server cert, then remove the old pin in a later release. Pin the cert the **app actually sees** (often CDN/edge). Test a deliberate wrong pin in staging before production.

## Repackaging detection (Android)

```typescript
await Fortress.configure({
  checks: { repackaging: true },
  expectedSigningCertificateSha256: 'your_release_cert_sha256_hex',
});
```

If `repackaging` is `true` without a cert hash, `configure` **rejects** with `E_CONFIG`.

```bash
keytool -list -v -keystore your-release.keystore -alias your-alias \
  | grep "SHA256:" | awk '{print $2}' | tr -d ':' | tr '[:upper:]' '[:lower:]'
```

### Play App Signing

| Key | Use for `expectedSigningCertificateSha256`? |
|-----|-----------------------------------------------|
| **App signing key** (Play Console → App signing) | **Yes** — what devices install |
| **Upload key** (local upload keystore) | **No** for production users — false positives |

Disable `repackaging` on debug builds (debug keystore never matches).

## Development builds

```typescript
await Fortress.configure({
  mode: __DEV__ ? 'dev' : 'prod',
  onCriticalThreat: 'log',
  // Explicit checks.tamper always wins over mode soft-defaults
});
```

Or toggle checks manually:

```typescript
await Fortress.configure({
  monitor: !__DEV__,
  checks: { tamper: !__DEV__, root: true, jailbreak: true },
});
```

**iOS Simulator:** several jailbreak/tamper probes are skipped or narrowed to avoid macOS-host false positives. Validate on a **physical device**.

## Example app

```sh
yarn install
yarn example start

# another terminal
yarn example android
# or
yarn example ios   # run pod install under example/ios first when native code changes
```

## Troubleshooting

### Build / prepare

Run from the **repo root**, not `example/`:

```sh
yarn install
yarn build   # Yarn 4 does not always run prepare on install
```

Use Node **24+** (see `.nvmrc`).

### iOS after upgrading to 2.x

```sh
cd ios && pod install
```

Needed so the pod picks up `cpp/` scoring sources and new Spec methods (`getThreatConfidence`, `getSslPinningStatus`, options-based `performPinnedRequest`).

### Android SSL not applying to `fetch()`

Another library may have replaced `OkHttpClientProvider`. Call `configureSslPinning` early and inspect `getSslPinningStatus().coversGlobalFetch` / `okHttpFactoryInstalled`.

## Migrating from 1.x

See **[MIGRATION_v2.md](./MIGRATION_v2.md)** for a step-by-step checklist (breaking changes, SSL, scoring, threat tuning).

## Roadmap

**2.0** is feature-complete for the committed scope (shared C++ scoring, API cleanup, SSL hardening, threat tuning, CI). Details: [CHANGELOG.md](./CHANGELOG.md).

**2.1+:** Expo config plugin, React hooks, optional Play Integrity / DeviceCheck, fuller E2E.

No mobile security library is unbreakable on a fully compromised device. Use layered detection, native enforcement, and **server-side** risk decisions for high-value flows.

## License

MIT
