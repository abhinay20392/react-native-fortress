#import <Foundation/Foundation.h>

#import "FortressThreatResult.h"

NS_ASSUME_NONNULL_BEGIN

@interface ThreatOrchestrator : NSObject

@property (nonatomic, assign, readonly) BOOL configured;
@property (nonatomic, assign, readonly) BOOL isMonitoring;
@property (nonatomic, assign, readonly) NSTimeInterval configuredPollIntervalMs;
@property (nonatomic, assign, readonly) NSTimeInterval lastPollAt;
@property (nonatomic, copy, readonly, nullable) NSString *configuredMode;
@property (nonatomic, copy, readonly) NSString *configuredExitOn;

- (void)configure:(NSDictionary *)config;
- (void)setMonitoring:(BOOL)monitoring;
- (NSArray<FortressThreatResult *> *)runIntegrityChecks;
- (NSArray<FortressThreatResult *> *)runTamperChecks;
- (NSArray<FortressThreatResult *> *)runAllChecks;
- (void)respondToThreats:(NSArray<FortressThreatResult *> *)threats;
- (void)showBlockOverlayWithMessage:(NSString *)message;
- (BOOL)isDeviceCompromised;
- (NSInteger)threatConfidence;
- (void)destroy;

@property (nonatomic, copy, readonly) NSArray<FortressThreatResult *> *lastThreats;

@end

NS_ASSUME_NONNULL_END
