#import <React/RCTEventEmitter.h>
#import <React/RCTBridgeModule.h>

NS_ASSUME_NONNULL_BEGIN

@interface FortressEventEmitter : RCTEventEmitter <RCTBridgeModule>

+ (void)emitThreat:(NSDictionary *)body;

@end

NS_ASSUME_NONNULL_END
