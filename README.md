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
    emulator: false,
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
  type: 'frida' | 'debugger' | 'hooking' | 'root' | 'jailbreak' | 'ssl_pin_failure' | 'emulator' | 'repackaging' | ...;
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
| `showBlockOverlay(message?)` | Force-show the native block_ui overlay (demos / custom policy) |
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
    emulator: false,    // opt-in; medium severity (alone ≠ compromised)
    repackaging: false, // Android only (see below)
  },
  // Triggers on high OR critical threats (v1.x). Prefer 'log' until you need hard fail.
  onCriticalThreat: 'log', // 'log' | 'block_ui' | 'exit'
  expectedSigningCertificateSha256: '...', // required when repackaging is enabled
});
```

### `onCriticalThreat` behavior (v1.x)

| Value | Behavior |
|-------|----------|
| `log` (default) | Log threats and emit `onFortressThreat` events |
| `exit` | Kill the process when a **high or critical** threat is seen during monitoring |
| `block_ui` | Show a **native** full-screen overlay (non-dismissible; does not rely on JS) |

The option name says “critical,” but **`exit` / `block_ui` currently apply to high and critical**. These policies run when **monitoring** detects threats (background poll), not from a standalone `runChecks()` alone.

`block_ui` needs a visible activity/window (app in foreground). It cannot be dismissed by the user in this release — force-quit to recover during testing.

To preview the overlay without waiting for a high/critical threat:

```typescript
await Fortress.showBlockOverlay('Optional custom message');
```
## Emulator / Simulator detection

Opt-in via `checks.emulator: true` (default **off**). Emits a single `emulator` threat at **medium** severity, so it alone does **not** make `isDeviceCompromised()` true.

```typescript
await Fortress.configure({
  checks: {
    emulator: !__DEV__, // or true in CI against emulators
  },
});
```

- **Android:** Build props (`goldfish`/`ranchu`/sdk), QEMU/Genymotion files, related system props
- **iOS:** `TARGET_OS_SIMULATOR`, `hw.machine` / `uname` x86 indicators, `SIMULATOR_DEVICE_NAME`

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

Hashes can be passed with or without the `sha256/` prefix (both are normalized).

- Use `Fortress.fetchPinned()` for security-sensitive requests (works on Android and iOS).
- On Android, `configureSslPinning` also hooks React Native's OkHttp client when called early.
- On iOS, third-party `fetch()` calls are not automatically pinned — use `fetchPinned()`.

### SSL pin failures and rotation

| Situation | What happens |
|-----------|----------------|
| Wrong / outdated pin | `fetchPinned` rejects with `E_SSL_PIN_FAILURE`; a `ssl_pin_failure` threat is emitted |
| Pinning not configured | Rejects with `E_SSL_PINNING` — call `configureSslPinning` first |
| Cert rotation | Ship a **backup** pin in `publicKeyHashes` before rotating the server cert, then remove the old pin in a later app release |
| CDN vs origin | Pin the public key of the certificate the **app actually sees** (often the CDN/edge cert) |

Always test a deliberate wrong pin in staging so you confirm failures are detectable before release.

## Repackaging detection (Android)

Opt-in check that your app is signed with your expected release certificate:

```typescript
await Fortress.configure({
  checks: { repackaging: true },
  expectedSigningCertificateSha256: 'your_release_cert_sha256_hex',
});
```

Get a signing cert SHA-256 (hex, no colons):

```bash
keytool -list -v -keystore your-release.keystore -alias your-alias \
  | grep "SHA256:" | awk '{print $2}' | tr -d ':' | tr '[:upper:]' '[:lower:]'
```

### Play App Signing vs upload key

If you use **Google Play App Signing**, end-user APKs/AABs are re-signed with Google's **app signing key**, not your local upload keystore.

| Key | Use for Fortress `expectedSigningCertificateSha256`? |
|-----|------------------------------------------------------|
| **App signing key** (Play Console → Setup → App signing) | **Yes** — this is what devices install |
| **Upload key** (your local keystore used to upload) | **No** for production users — causes false `repackaging` threats |

Copy the **SHA-256 certificate** fingerprint of the **app signing key** from Play Console (strip colons, lowercase). Disable `repackaging` in debug builds — the debug keystore will never match.

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

The example app follows this pattern: tamper stays off until you enable it on the Tamper tab.

**iOS Simulator notes:** several probes are skipped or narrowed (unix paths like `/bin/bash`, debugger, `DYLD_INSERT_LIBRARIES`, sandbox write, Cydia URL) to avoid false positives from the macOS host environment. Validate jailbreak/tamper behavior on a **physical device**.

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

v1.1 adds emulator detection, native `block_ui`, and `showBlockOverlay()` for demos. Planned v2 work includes shared C++ scoring, SSL `fetchPinned` options, threat tuning, Expo plugin, and optional Play Integrity / DeviceCheck modules.

No mobile security library is unbreakable on a fully compromised device. The goal is layered defense, early detection, and configurable response — with server-side risk scoring for high-value flows.

## License

MIT
