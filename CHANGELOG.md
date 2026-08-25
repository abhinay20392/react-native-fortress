# Changelog

## 2.0.0

### Breaking
- `configure` rejects with `E_CONFIG` when `checks.repackaging: true` without `expectedSigningCertificateSha256`
- Native `performPinnedRequest` now takes an options object (`{ url, method?, headers?, body? }`) instead of a bare URL string (JS `fetchPinned` still accepts a URL string)

### Added
- `exitOn: 'high' | 'critical'` — threshold for `exit` / `block_ui` (default `'high'`)
- `mode: 'dev' | 'prod'` — soft defaults for `checks.tamper` when omitted
- Optional `ThreatEvent` fields: `code`, `detector`, `evidence`
- `fetchPinned({ url, method, headers, body })` for non-GET pinned requests
- `getSslPinningStatus()` — configured hosts / pin counts / platform coverage
- Broader iOS SPKI support (EC P-384/P-521, RSA-3072/4096)
- Android OkHttp factory early install + re-assert against overwrite races
- Structured SSL reject `userInfo.reason` (`pin_mismatch`, `not_configured`, …)
- `threatTuning` — severityOverrides, allowlist, dedupeEvents
- `getThreatConfidence()` — shared C++ 0–100 score
- `MIGRATION_v2.md`

### Notes
- Shared C++ scoring (`configure({ scoring })`) remains the single compromise path (introduced in 1.1 / M2)

## 1.1.0

- Emulator detection (`checks.emulator`)
- Native `block_ui` overlay + `showBlockOverlay()`
- Shared C++ threat scoring + constant-time compare helpers
