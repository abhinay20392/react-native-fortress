#import "ThreatOrchestrator.h"

#import "FortressEventEmitter.h"
#import "ThreatScoring.h"
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
@property (nonatomic, copy) NSString *exitOn;
@property (nonatomic, copy, nullable) NSString *mode;
@property (nonatomic, copy) NSDictionary<NSString *, NSString *> *severityOverrides;
@property (nonatomic, copy) NSSet<NSString *> *allowlist;
@property (nonatomic, assign) BOOL dedupeEvents;
@property (nonatomic, copy, nullable) NSString *lastEmittedFingerprint;
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
        _exitOn = @"high";
        _severityOverrides = @{};
        _allowlist = [NSSet set];
        _dedupeEvents = YES;
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

- (NSString *)configuredMode
{
    return _mode;
}

- (NSString *)configuredExitOn
{
    return _exitOn ?: @"high";
}

- (void)configure:(NSDictionary *)config
{
    BOOL tamperExplicit = NO;

    id modeValue = config[@"mode"];
    if ([modeValue isKindOfClass:[NSString class]]) {
        self.mode = modeValue;
    }

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
            tamperExplicit = YES;
        }
        id emulator = checks[@"emulator"];
        if ([emulator isKindOfClass:[NSNumber class]]) {
            self.checksEmulator = [emulator boolValue];
        }
    }

    if (!tamperExplicit) {
        if ([self.mode isEqualToString:@"dev"]) {
            self.checksTamper = NO;
        } else if ([self.mode isEqualToString:@"prod"]) {
            self.checksTamper = YES;
        }
    }

    id criticalAction = config[@"onCriticalThreat"];
    if ([criticalAction isKindOfClass:[NSString class]]) {
        self.onCriticalThreat = criticalAction;
    }

    id exitOnValue = config[@"exitOn"];
    if ([exitOnValue isKindOfClass:[NSString class]]) {
        self.exitOn = [exitOnValue isEqualToString:@"critical"] ? @"critical" : @"high";
    }

    id scoring = config[@"scoring"];
    if ([scoring isKindOfClass:[NSDictionary class]]) {
        NSDictionary *scoringMap = (NSDictionary *)scoring;
        NSString *aloneAt =
            [scoringMap[@"aloneAt"] isKindOfClass:[NSString class]] ? scoringMap[@"aloneAt"] : nil;
        NSString *countAtOrAbove = [scoringMap[@"countAtOrAbove"] isKindOfClass:[NSString class]]
                                       ? scoringMap[@"countAtOrAbove"]
                                       : nil;
        NSInteger countThreshold = 0;
        if ([scoringMap[@"countThreshold"] isKindOfClass:[NSNumber class]]) {
            countThreshold = [scoringMap[@"countThreshold"] integerValue];
        }
        [FortressThreatScoring configureWithAloneAt:aloneAt
                                     countAtOrAbove:countAtOrAbove
                                     countThreshold:countThreshold];
    }

    id threatTuning = config[@"threatTuning"];
    if ([threatTuning isKindOfClass:[NSDictionary class]]) {
        NSDictionary *tuning = (NSDictionary *)threatTuning;
        id allowlist = tuning[@"allowlist"];
        if ([allowlist isKindOfClass:[NSArray class]]) {
            NSMutableSet<NSString *> *next = [NSMutableSet set];
            for (id item in (NSArray *)allowlist) {
                if ([item isKindOfClass:[NSString class]] && [(NSString *)item length] > 0) {
                    [next addObject:[(NSString *)item lowercaseString]];
                }
            }
            self.allowlist = next;
        }
        id overrides = tuning[@"severityOverrides"];
        if ([overrides isKindOfClass:[NSDictionary class]]) {
            NSMutableDictionary<NSString *, NSString *> *next = [NSMutableDictionary dictionary];
            [(NSDictionary *)overrides enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
                if (![key isKindOfClass:[NSString class]] || ![value isKindOfClass:[NSString class]]) {
                    return;
                }
                NSString *severity = [(NSString *)value lowercaseString];
                if ([severity isEqualToString:@"low"] || [severity isEqualToString:@"medium"] ||
                    [severity isEqualToString:@"high"] || [severity isEqualToString:@"critical"]) {
                    next[[(NSString *)key lowercaseString]] = severity;
                }
            }];
            self.severityOverrides = next;
        }
        id dedupe = tuning[@"dedupeEvents"];
        if ([dedupe isKindOfClass:[NSNumber class]]) {
            self.dedupeEvents = [dedupe boolValue];
        }
    }

    self.configured = YES;

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
    return [self applyTuningToThreats:threats];
}

- (NSArray<FortressThreatResult *> *)applyTuningToThreats:(NSArray<FortressThreatResult *> *)threats
{
    if (threats.count == 0) {
        return threats;
    }

    NSMutableArray<FortressThreatResult *> *tuned = [NSMutableArray array];
    for (FortressThreatResult *threat in threats) {
        NSString *typeKey = [threat.type lowercaseString] ?: @"";
        if ([self.allowlist containsObject:typeKey]) {
            continue;
        }

        NSString *override = self.severityOverrides[typeKey];
        if (override.length > 0 && ![override isEqualToString:threat.severity]) {
            FortressThreatResult *copy = [[FortressThreatResult alloc] init];
            copy.type = threat.type;
            copy.severity = override;
            copy.message = threat.message;
            copy.code = threat.code;
            copy.detector = threat.detector;
            copy.evidence = threat.evidence;
            [tuned addObject:copy];
        } else {
            [tuned addObject:threat];
        }
    }
    return tuned;
}

- (NSString *)fingerprintForThreats:(NSArray<FortressThreatResult *> *)threats
{
    NSMutableArray<NSString *> *parts = [NSMutableArray array];
    for (FortressThreatResult *threat in threats) {
        [parts addObject:[NSString stringWithFormat:@"%@:%@:%@",
                                                    [threat.type lowercaseString] ?: @"",
                                                    [threat.severity lowercaseString] ?: @"",
                                                    threat.code ?: @""]];
    }
    [parts sortUsingSelector:@selector(compare:)];
    return [parts componentsJoinedByString:@"|"];
}

- (BOOL)isDeviceCompromised
{
    return [FortressThreatScoring isCompromisedWithThreats:[self runAllChecks]];
}

- (NSInteger)threatConfidence
{
    return [FortressThreatScoring confidenceWithThreats:[self runAllChecks]];
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
    } else {
        self.lastEmittedFingerprint = nil;
    }
}

- (void)respondToThreats:(NSArray<FortressThreatResult *> *)threats
{
    if (threats.count == 0) {
        self.lastEmittedFingerprint = nil;
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
    NSString *fingerprint = [self fingerprintForThreats:threats];
    BOOL shouldEmit = !self.dedupeEvents || ![fingerprint isEqualToString:self.lastEmittedFingerprint];
    if (shouldEmit) {
        self.lastEmittedFingerprint = fingerprint;
    }

    BOOL shouldEnforce = NO;

    for (FortressThreatResult *threat in threats) {
        if (shouldEmit) {
            [FortressEventEmitter emitThreat:[threat toDictionary]];
        }

        if ([self.exitOn isEqualToString:@"critical"]) {
            if ([threat.severity isEqualToString:@"critical"]) {
                shouldEnforce = YES;
            }
        } else if ([threat.severity isEqualToString:@"high"] ||
                   [threat.severity isEqualToString:@"critical"]) {
            shouldEnforce = YES;
        }
    }

    if ([self.onCriticalThreat isEqualToString:@"exit"] && shouldEnforce) {
        NSLog(@"[Fortress] Threat at/above exitOn=%@ — exiting (onCriticalThreat=exit)", self.exitOn);
        exit(0);
        return;
    }

    if ([self.onCriticalThreat isEqualToString:@"block_ui"] && shouldEnforce) {
        NSMutableArray<NSString *> *lines = [NSMutableArray array];
        for (FortressThreatResult *threat in threats) {
            BOOL include = NO;
            if ([self.exitOn isEqualToString:@"critical"]) {
                include = [threat.severity isEqualToString:@"critical"];
            } else {
                include = [threat.severity isEqualToString:@"high"] ||
                          [threat.severity isEqualToString:@"critical"];
            }
            if (include) {
                [lines addObject:[NSString stringWithFormat:@"• %@: %@", threat.type, threat.message]];
            }
        }
        NSString *summary = lines.count > 0
                                ? [lines componentsJoinedByString:@"\n"]
                                : @"A security threat was detected.";
        NSLog(@"[Fortress] Threat at/above exitOn=%@ — showing block_ui overlay", self.exitOn);
        [UiBlocker showWithMessage:summary];
        return;
    }

    if (shouldEmit) {
        for (FortressThreatResult *threat in threats) {
            NSLog(@"[Fortress] Threat [%@] %@: %@",
                  threat.severity,
                  threat.type,
                  threat.message);
        }
    }
}

@end
