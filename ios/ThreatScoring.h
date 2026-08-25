#import <Foundation/Foundation.h>

@class FortressThreatResult;

NS_ASSUME_NONNULL_BEGIN

/**
 * ObjC++ facade over shared C++ scoring (`cpp/fortress_scoring.cpp`).
 * Android and iOS must use this path for compromise decisions.
 */
@interface FortressThreatScoring : NSObject

+ (void)configureWithAloneAt:(nullable NSString *)aloneAt
              countAtOrAbove:(nullable NSString *)countAtOrAbove
              countThreshold:(NSInteger)countThreshold;

+ (void)resetConfig;

+ (BOOL)isCompromisedWithThreats:(NSArray<FortressThreatResult *> *)threats;

/** Corroboration aid: C++ confidence 0–100 for the same threat set. */
+ (NSInteger)confidenceWithThreats:(NSArray<FortressThreatResult *> *)threats;

+ (BOOL)constantTimeEquals:(NSString *)left with:(NSString *)right;

+ (BOOL)constantTimeEqualsNormalizedHex:(NSString *)left with:(NSString *)right;

/** True if candidate matches any allowed pin using constant-time compares. */
+ (BOOL)constantTimeContains:(NSString *)candidate in:(NSArray<NSString *> *)allowed;

@end

NS_ASSUME_NONNULL_END
