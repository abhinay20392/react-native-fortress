import { describe, expect, it, jest } from '@jest/globals';
import { Fortress } from '../Fortress';

describe('Fortress (JS fallback)', () => {
  it('configures and returns status', async () => {
    await Fortress.configure({
      monitor: true,
      pollIntervalMs: 10_000,
      mode: 'dev',
      exitOn: 'critical',
    });

    const status = await Fortress.getStatus();

    expect(status.configured).toBe(true);
    expect(status.monitoring).toBe(true);
    expect(status.version).toBe('2.0.0');
    expect(status.mode).toBe('dev');
    expect(status.exitOn).toBe('critical');
  });

  it('rejects repackaging without certificate hash', async () => {
    await expect(
      Fortress.configure({
        checks: { repackaging: true },
      })
    ).rejects.toThrow(/E_CONFIG|expectedSigningCertificateSha256/);
  });

  it('returns stub threats from runChecks', async () => {
    const threats = await Fortress.runChecks();

    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0]).toMatchObject({
      severity: 'low',
      message: expect.any(String),
      timestamp: expect.any(Number),
      code: 'STUB_OK',
      detector: 'StubDetector',
    });
  });

  it('reports device as not compromised in stub mode', async () => {
    await expect(Fortress.isDeviceCompromised()).resolves.toBe(false);
  });

  it('supports addThreatListener subscription', () => {
    const callback = jest.fn();
    const subscription = Fortress.addThreatListener(callback);

    expect(subscription.remove).toEqual(expect.any(Function));
    subscription.remove();
  });

  it('supports showBlockOverlay in stub mode', async () => {
    await expect(Fortress.showBlockOverlay('demo')).resolves.toBeUndefined();
  });

  it('returns stub pinned fetch result for URL and options', async () => {
    await Fortress.configureSslPinning([
      { host: 'example.com', publicKeyHashes: ['abc='] },
    ]);

    const fromUrl = await Fortress.fetchPinned('https://example.com');
    expect(fromUrl).toMatchObject({
      ok: true,
      pinned: true,
      sslPinVerified: true,
      method: 'GET',
    });

    const fromOptions = await Fortress.fetchPinned({
      url: 'https://example.com/items',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"a":1}',
    });
    expect(fromOptions).toMatchObject({
      ok: true,
      url: 'https://example.com/items',
      method: 'POST',
    });

    const sslStatus = await Fortress.getSslPinningStatus();
    expect(sslStatus.configured).toBe(true);
    expect(sslStatus.hosts.length).toBeGreaterThan(0);
  });

  it('supports getThreatConfidence in stub mode', async () => {
    await expect(Fortress.getThreatConfidence()).resolves.toBe(0);
  });

  it('accepts threatTuning in configure', async () => {
    await Fortress.configure({
      threatTuning: {
        allowlist: ['emulator'],
        severityOverrides: { debugger: 'medium' },
        dedupeEvents: true,
      },
    });
    const status = await Fortress.getStatus();
    expect(status.configured).toBe(true);
  });
});
