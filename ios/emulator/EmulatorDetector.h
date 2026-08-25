#import <Foundation/Foundation.h>

#import "FortressThreatResult.h"

NS_ASSUME_NONNULL_BEGIN

@interface EmulatorDetector : NSObject

+ (NSArray<FortressThreatResult *> *)runChecks;

@end

NS_ASSUME_NONNULL_END
