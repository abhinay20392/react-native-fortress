#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>

NS_ASSUME_NONNULL_BEGIN

@interface UiBlocker : NSObject

/// Shows a full-screen, non-dismissible overlay. Safe to call from any thread.
+ (void)showWithMessage:(NSString *)message;
+ (void)showWithMessage:(NSString *)message force:(BOOL)force;

@end

NS_ASSUME_NONNULL_END
