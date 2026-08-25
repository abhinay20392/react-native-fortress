import { Fortress } from 'react-native-fortress';
import type { FortressConfig } from 'react-native-fortress';

/**
 * Safe defaults for the example app.
 * Prefer `mode` over ad-hoc `__DEV__` tamper toggles (v2).
 */
export function exampleFortressConfig(
  overrides: Partial<FortressConfig> = {}
): FortressConfig {
  const mode = overrides.mode ?? (__DEV__ ? 'dev' : 'prod');

  const checks = {
    root: true,
    jailbreak: true,
    /** Opt-in: useful on emulator/simulator demos. */
    emulator: true,
    sslPinning: false,
    repackaging: false,
    ...overrides.checks,
  };

  return {
    mode,
    monitor: overrides.monitor ?? true,
    pollIntervalMs: overrides.pollIntervalMs ?? 15_000,
    onCriticalThreat: overrides.onCriticalThreat ?? 'log',
    exitOn: overrides.exitOn ?? 'high',
    expectedSigningCertificateSha256:
      overrides.expectedSigningCertificateSha256,
    scoring: overrides.scoring,
    checks,
  };
}

export async function configureExampleFortress(
  overrides: Partial<FortressConfig> = {}
): Promise<void> {
  await Fortress.configure(exampleFortressConfig(overrides));
}
