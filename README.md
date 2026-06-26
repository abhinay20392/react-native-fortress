# react-native-fortress

Native-first mobile security for React Native: root/jailbreak detection, anti-tampering (Frida, debugger, hooks), and SSL pinning.

## Install

```sh
npm install react-native-fortress
# or
yarn add react-native-fortress
```

**iOS** — run `pod install` in your `ios/` directory after installing.

Requires React Native **0.73+**. Autolinking handles native setup.

## Quick start

Call `Fortress.configure()` early in your app (before sensitive screens or network calls):

```typescript
import { Fortress } from 'react-native-fortress';

await Fortress.configure({
  monitor: true,
  pollIntervalMs: 30_000,
  checks: {
    tamper: true,
    root: true,
    jailbreak: true,
    repackaging: false,
  },
  onCriticalThreat: 'log',
});

const compromised = await Fortress.isDeviceCompromised();
const threats = await Fortress.runChecks();
const status = await Fortress.getStatus();
```

## Listen for threats

Native monitoring emits events to JavaScript:

```typescript
const subscription = Fortress.addThreatListener((event) => {
  console.warn(event.type, event.severity, event.message);
});

// later
subscription.remove();
```

`event` shape:

```typescript
{
  type: 'frida' | 'debugger' | 'hooking' | 'root' | 'jailbreak' | 'ssl_pin_failure' | 'repackaging' | ...;
  severity: 'low' | 'medium' | 'high' | 'critical';
  message: string;
  platform: 'ios' | 'android';
  timestamp: number;
}
```

## API

| Method | Description |
|--------|-------------|
| `configure(config)` | Enable checks, monitoring interval, and threat response policy |
| `startMonitoring()` | Start native background polling |
| `stopMonitoring()` | Stop native background polling |
| `runChecks()` | Run all enabled checks on demand → `ThreatEvent[]` |
| `isDeviceCompromised()` | `true` when high/critical threats are detected |
| `getStatus()` | Monitoring state, platform, version, pinning status |
| `configureSslPinning(pins)` | Set SPKI pins per host |
| `fetchPinned(url)` | Native GET request using the pinned TLS stack |
| `addThreatListener(cb)` | Subscribe to live threat events |

### `configure` options

```typescript
await Fortress.configure({
  monitor: true,
  pollIntervalMs: 30_000,
  checks: {
    tamper: true,       // Frida, debugger, hook frameworks
    root: true,         // Android
    jailbreak: true,    // iOS
    repackaging: false, // Android only (see below)
  },
  onCriticalThreat: 'log', // 'log' | 'block_ui' | 'exit'
  expectedSigningCertificateSha256: '...', // required when repackaging is enabled
});
```

## SSL pinning

Pin TLS at the native layer using SPKI hashes (SHA-256, base64):

```typescript
await Fortress.configureSslPinning([
  {
    host: 'api.example.com',
    publicKeyHashes: [
      'PRIMARY_SPKI_HASH_BASE64=',
      'BACKUP_SPKI_HASH_BASE64=', // optional, for cert rotation
    ],
    includeSubdomains: true,
  },
]);

const response = await Fortress.fetchPinned('https://api.example.com/health');
// { ok, status, url, body, pinned, sslPinVerified }
```

**Extract a pin from your server** (replace host):

```bash
echo | openssl s_client -servername api.example.com -connect api.example.com:443 2>/dev/null \
  | openssl x509 -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary \
  | openssl enc -base64
```

Hashes can be passed with or without the `sha256/` prefix.

- Use `Fortress.fetchPinned()` for security-sensitive requests (works on Android and iOS).
- On Android, `configureSslPinning` also hooks React Native's OkHttp client when called early.
- On iOS, third-party `fetch()` calls are not automatically pinned — use `fetchPinned()`.

## Repackaging detection (Android)

Opt-in check that your app is signed with your release certificate:

```typescript
await Fortress.configure({
  checks: { repackaging: true },
  expectedSigningCertificateSha256: 'your_release_cert_sha256_hex',
});
```

Get your release cert SHA-256:

```bash
keytool -list -v -keystore your-release.keystore -alias your-alias \
  | grep "SHA256:" | awk '{print $2}' | tr -d ':' | tr '[:upper:]' '[:lower:]'
```

## Development builds

Debugger and tamper checks fire when you attach Android Studio or Xcode. Disable tamper monitoring in dev if needed:

```typescript
await Fortress.configure({
  monitor: !__DEV__,
  checks: {
    tamper: !__DEV__,
    root: true,
    jailbreak: true,
  },
});
```

## Example app

This repo includes a runnable example:

```sh
yarn install
yarn example start

# another terminal
yarn example android
# or
yarn example ios
```

## Troubleshooting

### `yarn prepare` or `yarn build` fails

Run commands from the **repo root** (`react-native-fortress/`), not from `example/`:

```sh
cd /path/to/react-native-fortress
yarn install
yarn build
```

`yarn build` and `yarn prepare` both compile `src/` → `lib/` via [react-native-builder-bob](https://github.com/callstack/react-native-builder-bob). Yarn 4 does **not** run `prepare` automatically on `yarn install` — run `yarn build` after cloning.

If you see `bob: command not found`, install dependencies first:

```sh
yarn install
```

Use Node **24+** (see `.nvmrc`). If a previous build failed, retry:

```sh
yarn build
```

## Future work

v1.0 ships a native-first foundation. Planned improvements:

### iOS testing and hardening

iOS support is implemented but **not fully tested** on physical devices and release builds yet. Future work includes:

- Device and simulator test matrix (debug vs release)
- SSL pinning validation against real hosts (EC/RSA certs, rotation, wrong-pin failures)
- Jailbreak/tamper false-positive tuning on newer iOS versions

### Multilevel defense (JS → Native → C++)

Today, JavaScript is a thin typed facade and most logic runs in Kotlin (Android) and Objective-C++ (iOS). A stronger model is planned where each layer corroborates the others — bypassing JS alone should not be enough.

```
┌─────────────────────────────────────┐
│  JS        policy, UX, bundle checks │
├─────────────────────────────────────┤
│  Native    platform APIs, orchestration │
├─────────────────────────────────────┤
│  C++       shared scoring, sensitive logic │
└─────────────────────────────────────┘
```

| Layer | Planned role |
|-------|----------------|
| **JavaScript** | Optional release bundle integrity checks, bridge tamper detection, dev/prod policy |
| **Native** | Root/jailbreak, Frida/debugger, SSL pinning, event emission (current focus) |
| **C++** | Shared threat scoring, constant-time compares, pin validation helpers — harder to patch via the JS bridge alone |

Layers should **corroborate** each other (e.g. C++ flags a threat → native emits → app responds), not trust a single boolean from one tier.

### Other planned features

| Area | Direction |
|------|-----------|
| Emulator detection | Platform heuristics, off by default in dev |
| `block_ui` policy | Native overlay for critical threats without relying on JS |
| Repackaging (iOS) | Team ID / bundle integrity signals (App Store–safe) |
| Expo | Config plugin for prebuild projects |
| Threat tuning | Per-threat severity config and allowlists |
| Tests | Native unit tests + example-app E2E on Android and iOS |
| Server attestation | Optional Play Integrity / DeviceCheck integration |

No mobile security library is unbreakable on a fully compromised device. The goal is layered defense, early detection, and configurable response — with server-side risk scoring for high-value flows.

## License

MIT
