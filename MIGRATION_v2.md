# Migrating to react-native-fortress 2.0

Guide for upgrading from **1.x** → **2.0**. Read this before publishing or bumping your app dependency.

Also see [CHANGELOG.md](./CHANGELOG.md) and the [README](./README.md) API reference.

---

## Install

```bash
yarn add react-native-fortress@2
# or
npm install react-native-fortress@2
```

**iOS (required):**

```bash
cd ios && pod install && cd ..
```

Native C++ scoring and new Turbo Module methods are included via the podspec. Skipping `pod install` causes missing symbols / Spec mismatches.

**Android:** clean rebuild after upgrade if you had a previous Fortress NDK build cached:

```bash
cd android && ./gradlew clean && cd ..
```

---

## Migration checklist

Use this as a PR checklist:

- [ ] Bump to `react-native-fortress@2` and run iOS `pod install`
- [ ] Add `exitOn` if you rely on `exit` / `block_ui` and want critical-only enforcement
- [ ] Fix any `checks.repackaging: true` configs missing `expectedSigningCertificateSha256`
- [ ] Prefer `fetchPinned({ url, method, headers, body })` for non-GET traffic
- [ ] Handle SSL errors via `error.code` + `error.userInfo.reason`
- [ ] Optionally adopt `mode`, `scoring`, `threatTuning`, `getThreatConfidence`, `getSslPinningStatus`
- [ ] Smoke-test: clean device, wrong SSL pin, `block_ui` / `log` policy

---

## Breaking changes

### 1. Repackaging without a cert hash fails configure

**1.x:** `checks.repackaging: true` without a hash was a silent no-op.  
**2.0:** `configure` **rejects** with `E_CONFIG`.

```ts
// ❌ throws E_CONFIG
await Fortress.configure({
  checks: { repackaging: true },
});

// ✅
await Fortress.configure({
  checks: { repackaging: true },
  expectedSigningCertificateSha256: 'your_app_signing_cert_sha256_hex',
});
```

If you use Play App Signing, use the **app signing key** fingerprint from Play Console (not the upload key). See README → Repackaging.

### 2. Native pinned request takes an options object

The Turbo Module method is now:

```ts
performPinnedRequest(options: { url; method?; headers?; body? })
```

**JS compatibility:** `Fortress.fetchPinned(url)` (string) still works and maps to `{ url, method: 'GET' }`.

```ts
// Still valid
await Fortress.fetchPinned('https://api.example.com/health');

// Preferred for 2.0
await Fortress.fetchPinned({
  url: 'https://api.example.com/items',
  method: 'POST',
  headers: { 'Content-Type': 'application/json', Authorization: 'Bearer …' },
  body: JSON.stringify({ id: 1 }),
});
```

Supported methods: `GET` | `POST` | `PUT` | `PATCH` | `DELETE` | `HEAD`.

If you called the native Spec directly with a string URL, update to an options map.

---

## Soft / additive changes (recommended)

### 3. `exitOn: 'high' | 'critical'`

Controls when `exit` and `block_ui` fire.

| Value | Behavior |
|-------|----------|
| `'high'` (default) | Same as 1.x — high **or** critical |
| `'critical'` | Enforce only on critical threats |

```ts
await Fortress.configure({
  onCriticalThreat: 'block_ui',
  exitOn: 'critical',
});
```

`runChecks()` also applies this policy (not only background monitoring).

### 4. `mode: 'dev' | 'prod'`

Soft defaults when `checks.tamper` is **omitted**:

| `mode` | Default `checks.tamper` |
|--------|-------------------------|
| `'dev'` | `false` |
| `'prod'` | `true` |
| omitted | library default (`true`) |

```ts
await Fortress.configure({
  mode: __DEV__ ? 'dev' : 'prod',
  onCriticalThreat: 'log',
});
```

Explicit `checks.tamper: true | false` always wins.

### 5. Richer `ThreatEvent`

Existing fields unchanged. New optional fields:

| Field | Example |
|-------|---------|
| `code` | `SSL_PIN_FAILURE`, `EMULATOR_DETECTED` |
| `detector` | `SslPinningManager`, `JailbreakDetector` |
| `evidence` | `{ url, method, signals, … }` |

Update logging / analytics if you want stable codes instead of parsing `message`.

### 6. Shared C++ scoring (`scoring`)

Same compromise path on Android and iOS (introduced in 1.1, still the source of truth in 2.0):

```ts
await Fortress.configure({
  scoring: {
    aloneAt: 'high', // any single ≥ this → compromised
    countAtOrAbove: 'medium', // count threats ≥ this
    countThreshold: 2, // N counted signals → compromised
  },
});
```

Defaults preserve 1.x behavior (`aloneAt: 'high'`, `countAtOrAbove: 'low'`, `countThreshold: 2`).

### 7. Threat tuning (`threatTuning`)

Applied after detectors, before scoring / emit / policy:

```ts
await Fortress.configure({
  threatTuning: {
    severityOverrides: { debugger: 'medium' },
    allowlist: ['emulator'], // drop these types
    dedupeEvents: true, // default — don't re-flood JS every poll
  },
});
```

| Field | Purpose |
|-------|---------|
| `severityOverrides` | Remap severity by type |
| `allowlist` | Drop types (internal / MDM / emulator farms) |
| `dedupeEvents` | Re-emit JS events only when the threat set changes; policy still runs each poll |

### 8. New APIs

```ts
const confidence = await Fortress.getThreatConfidence(); // 0–100 from C++

const ssl = await Fortress.getSslPinningStatus();
// ssl.configured, ssl.hosts[], ssl.coversGlobalFetch, ssl.platformNote

await Fortress.showBlockOverlay('Demo'); // force native block_ui overlay
```

### 9. Structured SSL errors

| Code | Typical `userInfo.reason` |
|------|---------------------------|
| `E_SSL_PIN_FAILURE` | `pin_mismatch` |
| `E_SSL_PINNING` | `not_configured` |
| `E_SSL_REQUEST` | `invalid_url` \| `unsupported_method` \| `network` |

```ts
try {
  await Fortress.fetchPinned({ url: 'https://api.example.com/health' });
} catch (error: any) {
  // error.code, error.userInfo?.reason, error.message
}
```

### 10. SSL platform coverage (document for your team)

| Platform | Global `fetch()` / XHR |
|----------|-------------------------|
| Android | Covered while Fortress OkHttp factory remains installed |
| iOS | **Not** covered — use `Fortress.fetchPinned` for sensitive traffic |

---

## Before / after config example

**1.x**

```ts
await Fortress.configure({
  monitor: true,
  checks: { tamper: !__DEV__, root: true, jailbreak: true },
  onCriticalThreat: 'log',
});

await Fortress.fetchPinned('https://api.example.com/health');
```

**2.0**

```ts
await Fortress.configure({
  mode: __DEV__ ? 'dev' : 'prod',
  monitor: true,
  checks: {
    root: true,
    jailbreak: true,
    emulator: false,
    repackaging: false,
  },
  onCriticalThreat: 'log',
  exitOn: 'high',
  scoring: {
    aloneAt: 'high',
    countAtOrAbove: 'low',
    countThreshold: 2,
  },
  threatTuning: {
    dedupeEvents: true,
  },
});

await Fortress.fetchPinned({
  url: 'https://api.example.com/health',
  method: 'GET',
});
```

---

## Verification

1. App starts and `getStatus()` reports `version: '2.0.0'` and `configured: true`
2. Wrong SSL pin → `E_SSL_PIN_FAILURE` / `reason: pin_mismatch` + `ssl_pin_failure` event
3. Valid pin → `fetchPinned` succeeds; `getSslPinningStatus().configured === true`
4. If using `block_ui`, confirm overlay on a high/critical signal (or `showBlockOverlay`)
5. If using `repackaging`, confirm configure fails without a hash and succeeds with the Play **app signing** SHA-256

---

## Need help?

- Public API: [README.md](./README.md)
- Release notes: [CHANGELOG.md](./CHANGELOG.md)
- Issues: https://github.com/abhinay20392/react-native-fortress/issues
