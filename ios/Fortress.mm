#import "Fortress.h"

#import "FortressEventEmitter.h"
#import "jailbreak/JailbreakDetector.h"
#import "ssl/SslPinningManager.h"
#import "ui/UiBlocker.h"

@implementation Fortress

- (instancetype)init
{
    self = [super init];
    if (self) {
        _orchestrator = [[ThreatOrchestrator alloc] init];
    }
    return self;
}

- (void)configure:(NSDictionary *)config
          resolve:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
    [self.orchestrator configure:config];
    resolve(nil);
}

- (void)startMonitoring:(RCTPromiseResolveBlock)resolve
                 reject:(RCTPromiseRejectBlock)reject
{
    [self.orchestrator setMonitoring:YES];
    resolve(nil);
}

- (void)stopMonitoring:(RCTPromiseResolveBlock)resolve
                reject:(RCTPromiseRejectBlock)reject
{
    [self.orchestrator setMonitoring:NO];
    resolve(nil);
}

- (void)runChecks:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
    NSArray<FortressThreatResult *> *results = [self.orchestrator runAllChecks];
    NSMutableArray *threats = [NSMutableArray array];
    for (FortressThreatResult *threat in results) {
        [threats addObject:[threat toDictionary]];
    }
    // Enforce onCriticalThreat for on-demand checks too (not only background polls).
    [self.orchestrator respondToThreats:results];
    resolve(threats);
}

- (void)isDeviceCompromised:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject
{
    resolve(@([self.orchestrator isDeviceCompromised]));
}

- (void)configureSslPinning:(NSArray *)pins
                    resolve:(RCTPromiseResolveBlock)resolve
                     reject:(RCTPromiseRejectBlock)reject
{
    [[SslPinningManager shared] configurePins:pins];
    resolve(nil);
}

- (void)performPinnedRequest:(NSString *)url
                     resolve:(RCTPromiseResolveBlock)resolve
                      reject:(RCTPromiseRejectBlock)reject
{
    [[SslPinningManager shared] performPinnedRequestWithURL:url
        resolve:^(NSDictionary *result) {
            resolve(result);
        }
        reject:^(NSString *code, NSString *message, NSError *error) {
            reject(code, message, error);
        }
        emitThreat:^(NSDictionary *threat) {
            [FortressEventEmitter emitThreat:threat];
        }];
}

- (void)getStatus:(RCTPromiseResolveBlock)resolve
           reject:(RCTPromiseRejectBlock)reject
{
    NSMutableDictionary *status = [@{
        @"monitoring": @(self.orchestrator.isMonitoring),
        @"configured": @(self.orchestrator.configured),
        @"sslPinningConfigured": @([SslPinningManager shared].configured),
        @"platform": @"ios",
        @"version": @"1.1.0",
        @"pollIntervalMs": @(self.orchestrator.configuredPollIntervalMs),
        @"lastThreatCount": @(self.orchestrator.lastThreats.count),
    } mutableCopy];

    if (self.orchestrator.lastPollAt > 0) {
        status[@"lastPollAt"] = @(self.orchestrator.lastPollAt);
    }

    resolve(status);
}

- (void)showBlockOverlay:(NSString *)message
                 resolve:(RCTPromiseResolveBlock)resolve
                  reject:(RCTPromiseRejectBlock)reject
{
    NSString *text = message.length > 0 ? message : @"Security threat detected (demo).";
    [self.orchestrator showBlockOverlayWithMessage:text];
    resolve(nil);
}

- (void)addListener:(NSString *)eventName
{
    // Required for NativeEventEmitter; events are emitted via RCTDeviceEventEmitter.
}

- (void)removeListeners:(double)count
{
    // Required for NativeEventEmitter.
}

- (std::shared_ptr<facebook::react::TurboModule>)getTurboModule:
    (const facebook::react::ObjCTurboModule::InitParams &)params
{
    return std::make_shared<facebook::react::NativeFortressSpecJSI>(params);
}

+ (NSString *)moduleName
{
    return @"Fortress";
}

@end
