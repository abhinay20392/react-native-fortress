#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SslPinningManager : NSObject

@property (nonatomic, assign, readonly) BOOL configured;

+ (instancetype)shared;

- (void)configurePins:(NSArray *)pins;
- (void)performPinnedRequestWithURL:(NSString *)url
                            resolve:(void (^)(NSDictionary *result))resolve
                             reject:(void (^)(NSString *code, NSString *message, NSError *_Nullable error))reject
                         emitThreat:(void (^)(NSDictionary *threat))emitThreat;

@end

NS_ASSUME_NONNULL_END
