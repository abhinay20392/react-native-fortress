#import "ThreatOrchestrator.h"

#import "FortressEventEmitter.h"
#import "emulator/EmulatorDetector.h"
#import "jailbreak/JailbreakDetector.h"
#import "tamper/TamperDetector.h"
#import "ui/UiBlocker.h"

@interface ThreatOrchestrator ()

@property (nonatomic, strong) dispatch_queue_t pollQueue;
@property (nonatomic, strong, nullable) dispatch_source_t pollTimer;
@property (nonatomic, assign) NSTimeInterval pollIntervalMs;
@property (nonatomic, assign) BOOL monitoring;
@property (nonatomic, assign) BOOL configured;
@property (nonatomic, assign) BOOL checksJailbreak;
@property (nonatomic, assign) BOOL checksTamper;
@property (nonatomic, assign) BOOL checksEmulator;
@property (nonatomic, copy) NSString *onCriticalThreat;
@property (nonatomic, assign, readwrite) NSTimeInterval lastPollAt;
@property (nonatomic, copy, readwrite) NSArray<FortressThreatResult *> *lastThreats;

@end

@implementation ThreatOrchestrator

- (instancetype)init
{
    self = [super init];
    if (self) {
        _pollQueue = dispatch_queue_create("com.fortress.poll", DISPATCH_QUEUE_SERIAL);
        _pollIntervalMs = 30000;
        _monitoring = NO;
        _checksJailbreak = YES;
        _checksTamper = YES;
        _checksEmulator = NO;
        _onCriticalThreat = @"log";
        _lastThreats = @[];
        _configured = NO;
    }
    return self;
}

- (BOOL)isMonitoring
{
    return _monitoring;
}

- (NSTimeInterval)configuredPollIntervalMs
{
    return _pollIntervalMs;
}

- (void)configure:(NSDictionary *)config
{
    self.configured = YES;

    id monitor = config[@"monitor"];
    if ([monitor isKindOfClass:[NSNumber class]] && [monitor boolValue]) {
        self.monitoring = YES;
    }

    id pollInterval = config[@"pollIntervalMs"];
    if ([pollInterval isKindOfClass:[NSNumber class]]) {
        self.pollIntervalMs = MAX([pollInterval doubleValue], 5000);
    }

    id checks = config[@"checks"];
    if ([checks isKindOfClass:[NSDictionary class]]) {
        id jailbreak = checks[@"jailbreak"];
        if ([jailbreak isKindOfClass:[NSNumber class]]) {
            self.checksJailbreak = [jailbreak boolValue];
        }
        id tamper = checks[@"tamper"];
        if ([tamper isKindOfClass:[NSNumber class]]) {
            self.checksTamper = [tamper boolValue];
        }
        id emulator = checks[@"emulator"];
        if ([emulator isKindOfClass:[NSNumber class]]) {
            self.checksEmulator = [emulator boolValue];
        }
    }

    id criticalAction = config[@"onCriticalThreat"];
    if ([criticalAction isKindOfClass:[NSString class]]) {
        self.onCriticalThreat = criticalAction;
    }

    if (self.monitoring) {
        [self startPolling];
    }
}

- (void)setMonitoring:(BOOL)monitoring
{
    _monitoring = monitoring;
    if (monitoring) {
        [self startPolling];
    } else {
        [self stopPolling];
    }
}

- (NSArray<FortressThreatResult *> *)runIntegrityChecks
{
    if (!self.checksJailbreak) {
        return @[];
    }

    return [JailbreakDetector runChecks];
}

- (NSArray<FortressThreatResult *> *)runTamperChecks
{
    if (!self.checksTamper) {
        return @[];
    }

    return [TamperDetector runChecks];
}

- (NSArray<FortressThreatResult *> *)runEmulatorChecks
{
    if (!self.checksEmulator) {
        return @[];
    }

    return [EmulatorDetector runChecks];
}

- (NSArray<FortressThreatResult *> *)runAllChecks
{
    NSMutableArray<FortressThreatResult *> *threats = [NSMutableArray array];
    [threats addObjectsFromArray:[self runIntegrityChecks]];
    [threats addObjectsFromArray:[self runTamperChecks]];
    [threats addObjectsFromArray:[self runEmulatorChecks]];
    return threats;
}

- (BOOL)isDeviceCompromised
{
    NSArray<FortressThreatResult *> *threats = [self runAllChecks];

    for (FortressThreatResult *threat in threats) {
        if ([threat.severity isEqualToString:@"high"] ||
            [threat.severity isEqualToString:@"critical"]) {
            return YES;
        }
    }

    return threats.count >= 2;
}

- (void)destroy
{
    [self stopPolling];
}

- (void)startPolling
{
    [self stopPolling];

    if (!self.monitoring) {
        return;
    }

    __weak __typeof__(self) weakSelf = self;
    dispatch_async(self.pollQueue, ^{
        __typeof__(self) strongSelf = weakSelf;
        if (strongSelf == nil) {
            return;
        }

        [strongSelf runPollCycle];

        strongSelf.pollTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, strongSelf.pollQueue);
        uint64_t intervalNs = (uint64_t)(strongSelf.pollIntervalMs * NSEC_PER_MSEC);
        dispatch_source_set_timer(strongSelf.pollTimer,
                                  dispatch_time(DISPATCH_TIME_NOW, intervalNs),
                                  intervalNs,
                                  (uint64_t)(1 * NSEC_PER_SEC));
        dispatch_source_set_event_handler(strongSelf.pollTimer, ^{
            [strongSelf runPollCycle];
        });
        dispatch_resume(strongSelf.pollTimer);
    });
}

- (void)stopPolling
{
    if (self.pollTimer != nil) {
        dispatch_source_cancel(self.pollTimer);
        self.pollTimer = nil;
    }
}

- (void)runPollCycle
{
    NSArray<FortressThreatResult *> *threats = [self runAllChecks];
    self.lastPollAt = [[NSDate date] timeIntervalSince1970] * 1000;
    self.lastThreats = threats;

    if (threats.count > 0) {
        [self respondToThreats:threats];
    }
}

- (void)respondToThreats:(NSArray<FortressThreatResult *> *)threats
{
    if (threats.count == 0) {
        return;
    }
    [self handleThreats:threats];
}

- (void)showBlockOverlayWithMessage:(NSString *)message
{
    [UiBlocker showWithMessage:message force:YES];
}

- (void)handleThreats:(NSArray<FortressThreatResult *> *)threats
{
    BOOL hasCritical = NO;
    BOOL hasHigh = NO;

    for (FortressThreatResult *threat in threats) {
        [FortressEventEmitter emitThreat:[threat toDictionary]];

        if ([threat.severity isEqualToString:@"critical"]) {
            hasCritical = YES;
        }
        if ([threat.severity isEqualToString:@"high"]) {
            hasHigh = YES;
        }
    }

    // v1.x: exit triggers on high OR critical (name is historical).
    // v2 will split this via exitOn — see docs/V2_ROADMAP.md M3.1.
    if ([self.onCriticalThreat isEqualToString:@"exit"] && (hasCritical || hasHigh)) {
        NSLog(@"[Fortress] High/critical threat detected — exiting (onCriticalThreat=exit)");
        exit(0);
        return;
    }

    if ([self.onCriticalThreat isEqualToString:@"block_ui"] && (hasCritical || hasHigh)) {
        NSMutableArray<NSString *> *lines = [NSMutableArray array];
        for (FortressThreatResult *threat in threats) {
            if ([threat.severity isEqualToString:@"high"] ||
                [threat.severity isEqualToString:@"critical"]) {
                [lines addObject:[NSString stringWithFormat:@"• %@: %@", threat.type, threat.message]];
            }
        }
        NSString *summary = lines.count > 0
                                ? [lines componentsJoinedByString:@"\n"]
                                : @"A high or critical security threat was detected.";
        NSLog(@"[Fortress] High/critical threat detected — showing block_ui overlay");
        [UiBlocker showWithMessage:summary];
        return;
    }

    for (FortressThreatResult *threat in threats) {
        NSLog(@"[Fortress] Threat [%@] %@: %@",
              threat.severity,
              threat.type,
              threat.message);
    }
}

@end
