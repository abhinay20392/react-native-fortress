#import <Foundation/Foundation.h>

#import "FortressThreatResult.h"

NS_ASSUME_NONNULL_BEGIN

@interface JailbreakDetector : NSObject

+ (NSArray<FortressThreatResult *> *)runChecks;
+ (BOOL)isCompromisedWithThreats:(NSArray<FortressThreatResult *> *)threats;

@end

NS_ASSUME_NONNULL_END
