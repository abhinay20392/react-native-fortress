#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface FortressThreatResult : NSObject

@property (nonatomic, copy) NSString *type;
@property (nonatomic, copy) NSString *severity;
@property (nonatomic, copy) NSString *message;
@property (nonatomic, copy, nullable) NSString *code;
@property (nonatomic, copy, nullable) NSString *detector;
@property (nonatomic, copy, nullable) NSDictionary *evidence;

- (NSDictionary *)toDictionary;

@end

NS_ASSUME_NONNULL_END
