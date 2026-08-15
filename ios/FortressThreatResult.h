#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface FortressThreatResult : NSObject

@property (nonatomic, copy) NSString *type;
@property (nonatomic, copy) NSString *severity;
@property (nonatomic, copy) NSString *message;

- (NSDictionary *)toDictionary;

@end

NS_ASSUME_NONNULL_END
