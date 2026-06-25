import { describe, expect, it, jest } from '@jest/globals';
import { Fortress } from '../Fortress';

describe('Fortress (JS fallback)', () => {
  it('configures and returns status', async () => {
    await Fortress.configure({ monitor: true, pollIntervalMs: 10_000 });

    const status = await Fortress.getStatus();

    expect(status.configured).toBe(true);
    expect(status.monitoring).toBe(true);
    expect(status.version).toBe('1.0.0');
  });

  it('returns stub threats from runChecks', async () => {
    const threats = await Fortress.runChecks();

    expect(threats.length).toBeGreaterThan(0);
    expect(threats[0]).toMatchObject({
      severity: 'low',
      message: expect.any(String),
      timestamp: expect.any(Number),
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

  it('returns stub pinned fetch result', async () => {
    await Fortress.configureSslPinning([
      { host: 'example.com', publicKeyHashes: ['abc='] },
    ]);

    const result = await Fortress.fetchPinned('https://example.com');

    expect(result).toMatchObject({
      ok: true,
      pinned: true,
      sslPinVerified: true,
    });
  });
});
