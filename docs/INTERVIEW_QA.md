# react-native-fortress — Interview Questions & Answers

Technical Q&A for interviews, code reviews, or architecture discussions about this library. Includes edge cases and limitations grounded in the v1.0 implementation.

---

## Table of contents

1. [Architecture & design](#1-architecture--design)
2. [React Native bridge](#2-react-native-bridge)
3. [Root & jailbreak detection](#3-root--jailbreak-detection)
4. [Anti-tampering](#4-anti-tampering)
5. [Threat scoring & orchestration](#5-threat-scoring--orchestration)
6. [SSL pinning](#6-ssl-pinning)
7. [Repackaging detection](#7-repackaging-detection)
8. [Platform differences](#8-platform-differences)
9. [Security limitations & threat model](#9-security-limitations--threat-model)
10. [Edge cases](#10-edge-cases)
11. [Testing & development](#11-testing--development)
12. [Scenario-based questions](#12-scenario-based-questions)

---

## 1. Architecture & design

### Q: What problem does react-native-fortress solve?

**A:** It provides **native-first mobile security** for React Native apps: root/jailbreak detection, anti-tampering (Frida, debugger, hook frameworks), and TLS certificate pinning. JavaScript is a thin typed facade; detection logic runs in Kotlin (Android) and Objective-C++ (iOS) so it is harder to bypass by patching JS alone.

---

### Q: Why is the library "native-first" instead of pure JavaScript?

**A:** Client-side security checks in JS are trivial to bypass — an attacker can hook the React Native bridge, replace `Fortress.isDeviceCompromised()` to always return `false`, or patch the JS bundle. Running checks in native code raises the bar: attackers must patch native binaries, hook system APIs, or instrument at a lower level (Frida, Xposed, etc.), which the library also tries to detect.

---

### Q: Describe the high-level architecture.

**A:**

```
┌─────────────────────────────────────────┐
│  JS (Fortress.native.ts)                │  Typed API, event listeners
├─────────────────────────────────────────┤
│  Turbo Module (FortressModule / Fortress)│  Bridge, promises, events
├─────────────────────────────────────────┤
│  ThreatOrchestrator                     │  Config, polling, scoring, policy
├──────────────┬──────────────────────────┤
│ RootDetector │ TamperDetector           │  Platform-specific detectors
│ Jailbreak    │ SslPinningManager        │
│ Repackaging  │                          │
└──────────────┴──────────────────────────┘
```

- **`ThreatOrchestrator`** — central coordinator: reads config, runs checks on demand or on a background poll interval, emits events, applies `onCriticalThreat` policy.
- **Detectors** — stateless objects that return `ThreatResult` / `FortressThreatResult` lists.
- **`ThreatScoring`** — shared compromise logic on Android (duplicated inline on iOS).

---

### Q: What is the public API surface?

**A:** `configure`, `startMonitoring`, `stopMonitoring`, `runChecks`, `isDeviceCompromised`, `getStatus`, `configureSslPinning`, `fetchPinned`, and `addThreatListener`. Types live in `src/types.ts` (`ThreatEvent`, `FortressConfig`, `SslPinConfig`, etc.).

---

## 2. React Native bridge

### Q: How does JS talk to native code?

**A:** Via a **Turbo Module** (`NativeFortress` spec). `Fortress.native.ts` wraps native methods and uses `NativeEventEmitter` for the `onFortressThreat` event stream. On non-native platforms (unit tests, web), Metro resolves `Fortress.ts` — a **stub** that always reports safe state.

---

### Q: Why are there two Fortress files — `Fortress.ts` and `Fortress.native.ts`?

**A:** React Native's platform extension resolution: `.native.ts` is used on iOS/Android; `.ts` is the fallback for Jest and unsupported targets. The stub prevents tests from crashing when the native module is absent, but **tests do not validate real security behavior** — only API shape.

---

### Q: How are threat events delivered to JavaScript?

**A:** Native code emits `onFortressThreat` via `RCTDeviceEventEmitter` / `emitDeviceEvent`. JS subscribes with `Fortress.addThreatListener()`. Each event includes `type`, `severity`, `message`, `platform`, and `timestamp`.

**Edge case:** If no listener is registered, events are still emitted natively and logged per `onCriticalThreat` policy — but the app UI will not react unless it subscribed.

---

### Q: What happens when the native module is destroyed?

**A:** On Android, `FortressModule.invalidate()` calls `orchestrator.destroy()`, which stops polling and quits the `HandlerThread`. Failing to stop would leak a background thread.

---

## 3. Root & jailbreak detection

### Q: How does Android root detection work?

**A:** `RootDetector` runs multiple heuristics:

| Check | What it looks for | Typical severity |
|-------|-------------------|------------------|
| `checkSuBinary` | Known `su` paths (`/system/bin/su`, Magisk paths, etc.) | high |
| `checkTestKeys` | `Build.TAGS` contains `test-keys` | medium |
| `checkSystemProperties` | `ro.debuggable=1`, `ro.secure=0` | medium |
| `checkMagisk` / `checkZygisk` | Magisk/Zygisk filesystem indicators | high |
| `checkSuCommand` | `which su` in PATH | high |

---

### Q: How does iOS jailbreak detection work?

**A:** `JailbreakDetector` checks:

- **Suspicious paths** — Cydia, Sileo, MobileSubstrate, `/var/jb`, etc.
- **Suspicious dylibs** — Substrate, Frida, SSLKillSwitch, etc. via `_dyld_image_count`
- **Fork violation** — `fork()` should fail in sandbox on non-jailbroken devices
- **Restricted path stat** — writing/reading outside sandbox
- **Cydia URL scheme** — `cydia://` handling

---

### Q: Why use multiple weak signals instead of one definitive check?

**A:** No single client-side check is reliable. Rooted/jailbroken devices can hide `su`, rename paths, or hook file APIs. Combining signals reduces false negatives at the cost of more tuning for false positives. `ThreatScoring` treats **two or more medium/low threats** as compromised even without a high/critical hit.

---

### Q: Can root detection be fooled?

**A:** Yes. Magisk Hide, kernel-level root, hooked `File.exists()`, patched `Build.TAGS`, or Frida intercepting `stat()` can hide indicators. This is expected — client-side checks are **risk signals**, not proof.

---

## 4. Anti-tampering

### Q: What tamper checks exist on Android?

**A:** `TamperDetector`:

1. **Frida in `/proc/self/maps`** — signatures like `frida`, `gum-js`, `linjector`
2. **Frida default ports** — TCP connect to `127.0.0.1:27042/27043/27049`
3. **Debugger** — `Debug.isDebuggerConnected()`
4. **TracerPid** — `/proc/self/status` where `TracerPid > 0`
5. **Hook frameworks** — `Class.forName` for Xposed/LSPosed classes
6. **Hook maps** — Xposed, LSPosed, Zygisk strings in memory maps

---

### Q: What tamper checks exist on iOS?

**A:** `TamperDetector`:

1. **Frida in loaded images** — `_dyld_get_image_name` scan
2. **`DYLD_INSERT_LIBRARIES`** — env var injection
3. **Debugger** — `sysctl` `P_TRACED` flag
4. **Hooking libraries** — Substrate, Substitute, Cycript in dyld images

---

### Q: Why does attaching a debugger trigger tamper detection?

**A:** Debuggers are used for reverse engineering. `Debug.isDebuggerConnected()` (Android) and `P_TRACED` (iOS) detect active debugging. This is intentional but causes **false positives in development** when using Android Studio or Xcode.

**Mitigation:** Disable tamper checks in dev:

```typescript
await Fortress.configure({
  monitor: !__DEV__,
  checks: { tamper: !__DEV__ },
});
```

---

### Q: How would an attacker bypass Frida port detection?

**A:** Run Frida on a non-default port, use `frida-gadget` embedded without opening 27042, or hook `Socket.connect` to fake connection failures. Map-based and class-based checks are additional layers, not guarantees.

---

## 5. Threat scoring & orchestration

### Q: When does `isDeviceCompromised()` return `true`?

**A:** Shared logic (`ThreatScoring` on Android, inline on iOS):

1. Any threat with severity **`high`** or **`critical`**, **or**
2. **Two or more** threats of any severity (e.g. multiple `medium` root signals)

Empty threat list → `false`.

---

### Q: Why treat two medium threats as compromised?

**A:** Individual medium signals (e.g. `test-keys` alone) may be benign on emulators or custom ROMs. Multiple independent weak signals increase confidence without requiring a single high-severity hit that sophisticated attackers might suppress.

**Edge case:** A device with `ro.debuggable=1` **and** `test-keys` returns compromised even though neither is `high`.

---

### Q: How does background monitoring work?

**A:**

- **Android:** Dedicated `HandlerThread` (`FortressPoll`) runs a `Runnable` on `pollIntervalMs` (minimum **5000 ms**).
- **iOS:** Serial `dispatch_queue` + `dispatch_source` timer with the same minimum interval.

Each cycle runs all enabled checks, updates `lastPollAt` / `lastThreats`, emits events, and applies critical-threat policy.

---

### Q: What are the `onCriticalThreat` options?

**A:**

| Value | Behavior |
|-------|----------|
| `log` (default) | Log warnings; emit events to JS |
| `exit` | `killProcess` (Android) or `exit(0)` (iOS) on high/critical |
| `block_ui` | **Not implemented** — logs a warning only |

**Edge case:** `exit` triggers on **high OR critical**, not only critical — despite the option name.

---

## 6. SSL pinning

### Q: What pinning model does the library use?

**A:** **SPKI (Subject Public Key Info) pinning** — SHA-256 hash of the public key, base64-encoded, optionally prefixed with `sha256/`. This survives certificate renewal if the same key pair is reused.

---

### Q: How is pinning applied on Android vs iOS?

**A:**

| Platform | Mechanism |
|----------|-----------|
| **Android** | OkHttp `CertificatePinner`; registers as `OkHttpClientFactory` so React Native's default OkHttp client can be pinned when configured early |
| **iOS** | Custom `NSURLSessionDelegate` validates SPKI hashes in the server trust chain |

**Important:** Use `Fortress.fetchPinned(url)` for guaranteed pinned requests. On iOS, arbitrary `fetch()` calls are **not** automatically pinned.

---

### Q: How does `fetchPinned` behave on pin failure?

**A:** The promise rejects with `E_SSL_PIN_FAILURE`, a `ssl_pin_failure` threat is emitted to listeners, and the result is not returned. On success, response includes `pinned: true` and `sslPinVerified: true`.

---

### Q: Why support multiple `publicKeyHashes` per host?

**A:** **Certificate rotation** — ship a backup pin before rotating the server cert so old app versions do not break. OkHttp and the iOS delegate accept a match on any hash in the chain.

---

### Q: What is `includeSubdomains`?

**A:** Also pins `*.host` (e.g. `api.example.com` → `*.api.example.com`). **Edge case:** It does not pin sibling domains (`other.example.com`) — only the exact host and its subdomains per OkHttp/iOS matching rules.

---

## 7. Repackaging detection

### Q: What is repackaging detection?

**A:** Android-only, **opt-in** check that the installed APK is signed with your expected release certificate SHA-256. Detects repackaged/modified APKs distributed outside your official signing pipeline.

---

### Q: How do you enable it?

**A:**

```typescript
await Fortress.configure({
  checks: { repackaging: true },
  expectedSigningCertificateSha256: 'abc123...', // hex, no colons
});
```

`RepackagingDetector.configure()` normalizes: trim, lowercase, strip `:`.

---

### Q: What happens if the cert does not match?

**A:** Returns a **`critical`** `repackaging` threat. With `onCriticalThreat: 'exit'`, the app terminates.

**Edge cases:**

- **Debug builds** use a debug keystore → mismatch vs release hash → false positive if enabled in dev.
- **Play App Signing** — use the **app signing key** hash Google uses for end users, not only your upload key.
- **Missing config** — if `repackaging: true` but no `expectedSigningCertificateSha256`, `isEnabled()` is false and checks return empty (no threat).
- **API 28+** uses `GET_SIGNING_CERTIFICATES`; older APIs use deprecated `GET_SIGNATURES`.

---

## 8. Platform differences

### Q: Which checks are platform-specific?

| Check | Android | iOS |
|-------|---------|-----|
| Root | ✅ | ❌ |
| Jailbreak | ❌ | ✅ |
| Repackaging | ✅ | ❌ (planned) |
| Tamper (Frida/debugger/hooks) | ✅ | ✅ |
| SSL pinning | ✅ (OkHttp + RN factory) | ✅ (`fetchPinned` only for RN fetch) |
| Emulator | Type exists, not implemented | Type exists, not implemented |

---

### Q: Does `checks.root` on iOS or `checks.jailbreak` on Android cause errors?

**A:** No — unused flags are ignored per platform. Orchestrators only read relevant keys.

---

## 9. Security limitations & threat model

### Q: Can this library make an app "unhackable"?

**A:** **No.** On a fully compromised device, a determined attacker can hook native functions, patch the APK/IPA, use kernel modules, or emulate clean responses to the bridge. The README states the goal is **layered defense, early detection, and configurable response** — plus server-side risk scoring for high-value flows.

---

### Q: What attacks does v1.0 **not** defend against?

**A:**

- Sophisticated Frida with hidden maps/ports and native API hooks
- JS-only bypass (partially — native checks still run, but UI logic in JS can be patched)
- MITM on **unpinned** network paths (e.g. iOS `fetch()` without `fetchPinned`)
- Emulator detection (typed but not implemented)
- Server attestation (Play Integrity / DeviceCheck — planned)
- `block_ui` native overlay (not implemented)

---

### Q: Why is ProGuard/R8 configuration included?

**A:** Release builds obfuscate Kotlin classes. `consumerProguardFiles` keeps Fortress module, detectors, and OkHttp `CertificatePinner.Builder.add` so pinning and bridge methods are not stripped or broken.

**Edge case:** Over-aggressive app-level ProGuard rules could still break reflection used to reset OkHttp client cache (`OkHttpClientProvider.client` field).

---

## 10. Edge cases

### Polling & configuration

| Scenario | Behavior |
|----------|----------|
| `pollIntervalMs: 1000` | Coerced to **minimum 5000 ms** |
| `configure()` without `monitor: true` | Config stored; polling does not start until `startMonitoring()` or `monitor: true` |
| `configure()` called twice | Overwrites previous check flags and interval; restarts polling if monitoring |
| Threat during poll + manual `runChecks()` | Both emit events / return results independently |

### Threat severity

| Scenario | `isDeviceCompromised` |
|----------|----------------------|
| Single `medium` root signal | `false` |
| Two `medium` signals | `true` |
| One `high` debugger | `true` |
| Frida maps (`critical`) | `true` |

### SSL pinning

| Scenario | Result |
|----------|--------|
| `fetchPinned` before `configureSslPinning` | Rejects with `E_SSL_PINNING` |
| Wrong pin | Rejects + `ssl_pin_failure` event |
| Hash without `sha256/` prefix | Normalized automatically |
| Empty `host` or empty hashes in config | Entry skipped silently |
| CDN serves different cert than origin | Pin must match actual cert chain presented to the app |

### Repackaging

| Scenario | Result |
|----------|--------|
| `repackaging: true`, no cert hash | Check disabled (`isEnabled() == false`) |
| Internal enterprise build with different cert | Critical repackaging threat |
| Certificate read throws | `getSigningCertificateSha256` returns null → no threat (fail-open) |

### Development

| Scenario | Result |
|----------|--------|
| Xcode debugger attached | `debugger` high threat |
| Android Studio debugger | Same |
| Emulator with `test-keys` | May accumulate medium threats → compromised at 2+ |

### iOS-specific

| Scenario | Notes |
|----------|-------|
| iOS Simulator | Jailbreak checks may behave differently; not fully tested in v1.0 |
| `fork()` on modern iOS | Sandbox behavior evolves; fork check may need tuning |
| App Store review | Aggressive `exit` on jailbreak may affect review if triggered on clean devices |

### Android-specific

| Scenario | Notes |
|----------|-------|
| `/proc/self/maps` unreadable | Frida map check skipped (null) — fail-open for that check |
| Scoped storage / SELinux | Some path checks may not apply on all API levels |
| Magisk DenyList | May hide paths from file-based checks |

---

## 11. Testing & development

### Q: What do unit tests actually verify?

**A:** Jest runs against `Fortress.ts` stub — API contracts, subscription `remove()`, stub `fetchPinned` success. **They do not run native detectors.**

---

### Q: How should you test native security behavior?

**A:** Use the **example app** on real devices: rooted Android, jailbroken iOS (carefully), Frida attached, wrong SSL pins, debug vs release builds. Future work includes native unit tests and E2E matrices (documented in README).

---

### Q: When should you call `Fortress.configure()`?

**A:** As early as possible — before sensitive screens and **before** network calls if you rely on Android OkHttp factory hooking for pinning.

---

## 12. Scenario-based questions

### Q: A user reports the app exits on launch in production. What do you investigate?

**A:**

1. Is `onCriticalThreat: 'exit'` set?
2. Are tamper/root checks enabled in release while users sideload debug builds?
3. Is `repackaging` enabled with wrong cert hash (Play App Signing mismatch)?
4. Collect `runChecks()` output and threat listener logs.
5. Check for false positives: custom ROMs, enterprise MDM, Chinese OEM builds with unusual `Build.TAGS`.

---

### Q: Security team wants pinning on all API calls. What do you recommend?

**A:**

1. Call `configureSslPinning` at startup with primary + backup pins.
2. Route **all** sensitive traffic through `Fortress.fetchPinned()` (especially on iOS).
3. On Android, call pinning config before RN initializes networking; verify third-party SDKs use OkHttp or pin separately.
4. Plan rotation: add backup pin → deploy app → rotate server cert → remove old pin in next release.

---

### Q: How would you extend the library with emulator detection?

**A:** Add `EmulatorDetector` per platform (Build props, QEMU files, sensor heuristics), wire into `ThreatOrchestrator` behind `checks.emulator` (type already exists in `FortressChecksConfig`), default **off in dev**, tune severity to `medium` to avoid single-signal compromise unless paired with other signals.

---

### Q: How would multilevel JS → Native → C++ defense work (planned)?

**A:** Each layer independently runs checks and **corroborates** others — e.g. C++ computes scoring with constant-time compares, native orchestrates platform APIs, JS applies policy/UX. Bypassing JS alone should not silence native/C++ signals. Events would still flow native → JS for UI response.

---

### Q: Why might `getStatus().lastThreatCount` be 0 while `runChecks()` returns threats?

**A:** `lastThreatCount` reflects the **last background poll**, not on-demand `runChecks()`. If monitoring is off or no poll has run yet, it can be 0.

---

### Q: Compare `runChecks()` vs `isDeviceCompromised()`.

**A:**

- `runChecks()` — returns full `ThreatEvent[]` for logging/analytics.
- `isDeviceCompromised()` — runs the same checks but returns a single boolean via `ThreatScoring`.

Both execute detectors at call time; neither caches results between calls except the orchestrator's `lastThreats` from polling.

---

## Quick reference — threat types

| Type | Source | Typical severity |
|------|--------|------------------|
| `root` | Android `RootDetector` | medium–high |
| `jailbreak` | iOS `JailbreakDetector` | medium–high |
| `frida` | Tamper detectors | high–critical |
| `debugger` | Tamper detectors | high |
| `hooking` | Xposed/Substrate/etc. | high–critical |
| `repackaging` | Android signing mismatch | critical |
| `ssl_pin_failure` | Pinned request MITM/wrong cert | high |
| `emulator` | Not implemented in v1.0 | — |

---

## Quick reference — interview sound bites

- **"Native-first"** — security logic in Kotlin/ObjC++, JS is not trusted.
- **"Heuristic, not proof"** — combine signals; expect bypass on dedicated attackers.
- **"Fail-open vs fail-closed"** — unreadable `/proc` skips checks (open); repackaging mismatch is critical (closed); SSL pin failure rejects request (closed).
- **"Dev vs prod"** — disable tamper in `__DEV__`; enable repackaging only in release with correct cert.
- **"Platform asymmetry"** — Android hooks OkHttp globally; iOS requires `fetchPinned` for pinning.

---

*Based on react-native-fortress v1.0.0. Re-read native sources when preparing for deep system-design interviews — detection lists and policies may change in future releases.*
