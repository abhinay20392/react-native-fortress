import { TurboModuleRegistry, type TurboModule } from 'react-native';

export interface Spec extends TurboModule {
  configure(config: Object): Promise<void>;
  startMonitoring(): Promise<void>;
  stopMonitoring(): Promise<void>;
  runChecks(): Promise<Object[]>;
  isDeviceCompromised(): Promise<boolean>;
  configureSslPinning(pins: Object[]): Promise<void>;
  performPinnedRequest(url: string): Promise<Object>;
  getStatus(): Promise<Object>;
  addListener(eventName: string): void;
  removeListeners(count: number): void;
}

export default TurboModuleRegistry.getEnforcing<Spec>('Fortress');
