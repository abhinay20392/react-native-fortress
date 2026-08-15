import { Fortress } from 'react-native-fortress';
import type { FortressConfig } from 'react-native-fortress';

/**
 * Safe defaults for the example app.
 * In __DEV__, tamper monitoring is off so IDE debuggers do not flood threats / confuse demos.
 * Enable tamper explicitly from the Tamper tab when you want to exercise those checks.
 */
export function exampleFortressConfig(
  overrides: Partial<FortressConfig> = {}
): FortressConfig {
  const checks = {
    root: true,
    jailbreak: true,
    tamper: !__DEV__,
    sslPinning: false,
    repackaging: false,
    ...overrides.checks,
  };

  return {
    monitor: overrides.monitor ?? true,
    pollIntervalMs: overrides.pollIntervalMs ?? 15_000,
    onCriticalThreat: overrides.onCriticalThreat ?? 'log',
    expectedSigningCertificateSha256:
      overrides.expectedSigningCertificateSha256,
    checks,
  };
}

export async function configureExampleFortress(
  overrides: Partial<FortressConfig> = {}
): Promise<void> {
  await Fortress.configure(exampleFortressConfig(overrides));
}
