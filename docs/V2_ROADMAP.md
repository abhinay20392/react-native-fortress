# react-native-fortress — v2 Roadmap

Plan for a major release built on the v1.0 native-first foundation. Client-side checks remain bypassable on a fully compromised device; v2 aims for **layered detection, native enforcement, and optional server attestation** — not an unbreakable client.

**Current baseline:** v1.0.1 (Turbo Module, Kotlin + ObjC++, JS facade)

---

## Goals

1. Finish APIs already documented but incomplete (`block_ui`, `emulator`)
2. Share sensitive logic in C++ so Android/iOS cannot drift
3. Make SSL pinning production-grade (methods, iOS story, key types)
4. Harden iOS with a real device/release test matrix
5. Improve DX (Expo, threat tuning) without abandoning the native-first model

---

## Non-goals for 2.0

- Guaranteeing detection against kernel-level or dedicated Frida bypass
- Replacing server-side auth / risk engines
- Full rewrite of detectors from scratch (iterate on v1)

---

## Effort legend

| Size | Meaning (rough) |
|------|-----------------|
| **S** | ~0.5–2 days |
| **M** | ~3–5 days |
| **L** | ~1–2 weeks |
| **XL** | ~2–4+ weeks (multi-platform or infra-heavy) |

Estimates assume one engineer familiar with the repo; parallelize Android/iOS where noted.

---

## Release train

| Track | Version | Theme |
|-------|---------|--------|
| Patch / minor | **1.x** | iOS FP fixes, SSL bugfixes, docs — no breaking API |
| Major | **2.0** | Core promises + C++ scoring + SSL API + threat tuning |
| Follow-on | **2.1+** | Expo, attestation plugins, iOS integrity, E2E CI |

```
1.x patches  →  2.0 core  →  2.1 DX & attestation  →  2.x hardening
```

---

## Milestone 0 — v1.x stabilizers ✅ (shipped in 1.0.1)

Keep 1.x usable while 2.0 is in flight. Prefer **no breaking changes**.

| ID | Item | Effort | Status | Notes |
|----|------|--------|--------|-------|
| M0.1 | iOS jailbreak/tamper false-positive tuning | M | Done | Simulator skips noisy unix paths, debugger, DYLD insert, sandbox write, Cydia URL; tighter dylib matching |
| M0.2 | SSL pin failure messaging / docs | S | Done | README failure/rotation table; richer native reject messages |
| M0.3 | Document Play App Signing vs upload key | S | Done | README repackaging section |
| M0.4 | Example app `__DEV__` safe defaults for tamper | S | Done | `fortressConfig.ts`; Tamper tab opt-in enable |

**Exit criteria:** Known iOS FP issues documented or fixed; no silent API breaks.

---

## Milestone 1 — Finish v1 promises (2.0 must-have)

| ID | Item | Effort | Platforms | Status | Notes |
|----|------|--------|-----------|--------|-------|
| M1.1 | Implement **`block_ui`** native overlay | L | Android + iOS | Pending | Full-screen block without relying on JS; dismiss policy TBD |
| M1.2 | **Emulator detection** behind `checks.emulator` | M | Android + iOS | **Done** | Opt-in, medium severity; Android Build/QEMU + iOS Simulator signals |
| M1.3 | Wire emulator into `ThreatOrchestrator` + types | S | Both | **Done** | Default off; JSDoc + README |
| M1.4 | iOS **device + release** validation matrix | L | iOS | Pending | Debug/release, simulator/device, pin pass/fail |
| M1.5 | Align `onCriticalThreat` behavior with docs | S | Both | **Done** | Documented: `exit` fires on high **or** critical; logs clarified |

**Exit criteria:** `block_ui` and `emulator` work end-to-end; iOS matrix results recorded in repo (checklist or CI notes).

---

## Milestone 2 — Shared C++ core (2.0 architecture)

`package.json` already ships `cpp/` in `files`, but **no C++ sources exist yet**.

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| M2.1 | Scaffold C++ Turbo / JNI / ObjC++ bridge | L | Shared lib linked from Android NDK + iOS pod |
| M2.2 | Move **ThreatScoring** into C++ | M | Single source of truth; remove Android/iOS drift |
| M2.3 | Constant-time pin / cert hash compare helpers | M | Used by SSL managers |
| M2.4 | Severity thresholds + “N medium signals = compromised” config | M | Driven from JS config → native → C++ |
| M2.5 | Corroboration hook (native result + C++ score) | M | JS must not be the only gate for compromise |

**Exit criteria:** Android and iOS call the same C++ scoring path; unit tests for scoring in C++ or via native tests.

**Suggested layout:**

```
cpp/
  fortress_scoring.hpp / .cpp
  fortress_crypto.hpp / .cpp   # constant-time compare, hash normalize
android/.../jni/               # JNI wrappers
ios/...                        # ObjC++ wrappers
```

---

## Milestone 3 — API cleanup (breaking — justify 2.0)

| ID | Item | Effort | Breaking? | Notes |
|----|------|--------|-----------|-------|
| M3.1 | Split exit policy: `exitOn: 'high' \| 'critical'` | S | Yes | Or rename `onCriticalThreat` semantics |
| M3.2 | Fail configure when `repackaging: true` without cert hash | S | Yes | Stop silent no-op |
| M3.3 | `fetchPinned(options)` — method, headers, body | M | Yes | Replace URL-only GET |
| M3.4 | Richer `ThreatEvent` (code, detector, evidence) | M | Soft | Keep old fields; add optional fields if possible |
| M3.5 | Explicit `mode: 'dev' \| 'prod'` | S | Soft | Prefer over documenting only `__DEV__` |
| M3.6 | Migration guide `docs/MIGRATION_v2.md` | S | — | Required before publish |

**Exit criteria:** Changelog + migration doc; example app updated to v2 API.

---

## Milestone 4 — SSL pinning production grade (2.0 must-have)

| ID | Item | Effort | Platforms | Notes |
|----|------|--------|-----------|-------|
| M4.1 | Full HTTP API for pinned requests | M | Both | GET/POST/PUT/DELETE + headers/body |
| M4.2 | Broader iOS SPKI key support | M | iOS | Beyond EC P-256 / RSA-2048 heuristics |
| M4.3 | Stronger Android early OkHttp factory guarantees | M | Android | Document + harden race with other factories |
| M4.4 | iOS pinning story for app traffic | L | iOS | Wrapper, interceptor pattern, or documented limitations |
| M4.5 | Pin rotation helpers / status | S | Both | Report configured hosts; backup-pin docs |
| M4.6 | Structured pin-failure errors | S | Both | Stable error codes for app UX |

**Exit criteria:** Example app demos pass + fail pins on both platforms; rotation documented.

---

## Milestone 5 — Threat tuning (2.0 should-have)

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| M5.1 | Per-threat severity overrides | M | e.g. treat `debugger` as medium in staging |
| M5.2 | Allowlists (threat type / build flavor) | M | Internal builds, MDM ROMs |
| M5.3 | Event dedupe / coalesce on poll | S | Avoid flooding JS every 30s |
| M5.4 | Optional confidence score API | M | Complement boolean `isDeviceCompromised` |

**Exit criteria:** Config schema documented; unit tests for scoring with overrides.

---

## Milestone 6 — Platform parity & attestation (2.1+)

| ID | Item | Effort | Track |
|----|------|--------|-------|
| M6.1 | iOS integrity / Team ID / bundle signals | L | 2.1 |
| M6.2 | Optional Play Integrity module | XL | 2.1+ |
| M6.3 | Optional DeviceCheck / App Attest module | XL | 2.1+ |
| M6.4 | Server attestation callback pattern | M | 2.1 | App supplies verifier; Fortress collects signals |

Keep attestation **optional** so the core package stays lean and App Store / Play policy–safe.

---

## Milestone 7 — DX & ecosystem (2.1+)

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| M7.1 | Expo config plugin (prebuild) | L | Autolinking + iOS pods / Android gradle |
| M7.2 | React hooks (`useFortressStatus`, `useThreatListener`) | S | Thin JS wrappers |
| M7.3 | TypeScript stricter Turbo Module types | S | Less `Object` in `NativeFortress` |
| M7.4 | Changelog automation / release checklist | S | Tag + npm + GitHub release |

---

## Milestone 8 — Quality & CI (parallel with 2.0 / 2.1)

| ID | Item | Effort | Notes |
|----|------|--------|-------|
| M8.1 | Android JVM unit tests for detectors / scoring | L | Robolectric or pure Kotlin where possible |
| M8.2 | iOS XCTest for jailbreak/tamper/SSL helpers | L | Mock where needed |
| M8.3 | C++ scoring unit tests | M | After M2 |
| M8.4 | Example E2E smoke (Maestro / Detox) | XL | Debug + one release path |
| M8.5 | CI: lint + typecheck + Android compile + iOS compile | M | Block merges on red |
| M8.6 | Consumer ProGuard / R8 regression check | S | Example minify release |

**Exit criteria for 2.0:** At least M8.1 or M8.2 started; M8.5 green. Full E2E can land in 2.1.

---

## Suggested 2.0 scope (committed)

Treat these as the **definition of done** for publishing `2.0.0`:

| # | Deliverable | Milestones |
|---|-------------|------------|
| 1 | `block_ui` implemented | M1.1 |
| 2 | Emulator detection | M1.2–M1.3 |
| 3 | Shared C++ scoring (+ pin compare if feasible) | M2.1–M2.3 |
| 4 | SSL `fetchPinned` options API + iOS key hardening | M3.3, M4.1–M4.2 |
| 5 | iOS validation matrix documented | M1.4 |
| 6 | Threat tuning (severity / allowlist) | M5.1–M5.2 |
| 7 | Breaking API cleanup + migration guide | M3.* |
| 8 | CI compile gates | M8.5 |

**Deferred to 2.1+:** Expo plugin, Play Integrity / DeviceCheck, full E2E, iOS repackaging, signature obfuscation arms race.

---

## Rough calendar (single engineer)

| Phase | Duration | Focus |
|-------|----------|--------|
| 1.x polish | 1–2 weeks | M0 |
| 2.0 M1 + M3 | 2–3 weeks | block_ui, emulator, API breaks |
| 2.0 M2 | 2–3 weeks | C++ scaffold + scoring |
| 2.0 M4 + M5 | 2–3 weeks | SSL + threat tuning |
| 2.0 harden + ship | 1–2 weeks | matrix, migration, CI, npm |

**Total ~8–13 weeks** wall-clock for a credible 2.0, depending on iOS device access and how deep SSL/iOS pinning goes.

Parallelize: Android `block_ui` + emulator while iOS matrix runs; C++ after scoring API is frozen.

---

## Risk register

| Risk | Mitigation |
|------|------------|
| iOS App Store rejection of aggressive jailbreak/`exit` | Prefer `block_ui` + server deny; soft defaults for store builds |
| OkHttp factory conflicts with other RN libs | Document order; provide explicit `setFactory` helper |
| C++ build complexity (NDK / pods) | Ship scoring-first; crypto helpers second |
| False positives on OEM / MDM devices | Allowlists + severity overrides (M5) |
| Scope creep into “anti-Frida arms race” | Cap 2.0 at layered signals + native UI; leave obfuscation for later |
| Attestation SDK size / policy | Separate optional packages (`react-native-fortress-play-integrity`) |

---

## Success metrics

- Example app demonstrates: clean device, emulator, wrong SSL pin, `block_ui` on critical
- Android and iOS report the **same** compromise decision for identical synthetic threat sets (C++ scoring)
- Migration guide lets a v1 consumer upgrade in **&lt; 1 hour** for typical configs
- npm `2.0.0` + git tag `v2.0.0` + GitHub release notes

---

## Open decisions (resolve before coding M3)

1. **`exit` severity threshold** — keep high+critical, or critical-only by default?
2. **`block_ui` dismiss** — never, local PIN, or app callback only?
3. **iOS global fetch pinning** — in-scope for 2.0 or document-only limitation until 2.1?
4. **Monorepo packages** — single npm package vs core + attestation add-ons?
5. **Min RN version** — stay 0.73+ or bump with New Architecture–only assumptions?

---

## Related docs

- [README.md](../README.md) — public API and Future work
- [INTERVIEW_QA.md](./INTERVIEW_QA.md) — architecture, edge cases, threat model

---

*Living document — update milestone IDs and effort when scope is cut or expanded before the 2.0 tag.*
