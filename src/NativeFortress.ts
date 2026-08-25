import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  configure(config: Object): Promise<void>;
  startMonitoring(): Promise<void>;
  stopMonitoring(): Promise<void>;
  runChecks(): Promise<Object[]>;
  isDeviceCompromised(): Promise<boolean>;
  /** C++ confidence score 0–100 for the current tuned threat set. */
  getThreatConfidence(): Promise<number>;
  configureSslPinning(pins: Object[]): Promise<void>;
  /** Pinned HTTP request — `{ url, method?, headers?, body? }`. */
  performPinnedRequest(options: Object): Promise<Object>;
  /** Configured hosts / pin counts and platform coverage notes. */
  getSslPinningStatus(): Promise<Object>;
  getStatus(): Promise<Object>;
  /** Show the native block_ui overlay immediately (for demos / custom enforcement). */
  showBlockOverlay(message: string): Promise<void>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Fortress');
