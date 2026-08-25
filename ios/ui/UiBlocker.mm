#import "UiBlocker.h"

@implementation UiBlocker

static UIWindow *_blockWindow = nil;
static BOOL _showing = NO;

+ (void)showWithMessage:(NSString *)message
{
    [self showWithMessage:message force:NO];
}

+ (void)showWithMessage:(NSString *)message force:(BOOL)force
{
    if (_showing && !force) {
        NSLog(@"[Fortress] block_ui already visible — skip");
        return;
    }

    void (^present)(void) = ^{
        if (_showing && !force) {
            return;
        }
        _showing = YES;

        UIWindowScene *scene = nil;
        for (UIScene *candidate in UIApplication.sharedApplication.connectedScenes) {
            if (candidate.activationState == UISceneActivationStateForegroundActive &&
                [candidate isKindOfClass:[UIWindowScene class]]) {
                scene = (UIWindowScene *)candidate;
                break;
            }
        }

        if (scene == nil) {
            for (UIScene *candidate in UIApplication.sharedApplication.connectedScenes) {
                if ([candidate isKindOfClass:[UIWindowScene class]]) {
                    scene = (UIWindowScene *)candidate;
                    break;
                }
            }
        }

        if (_blockWindow != nil) {
            _blockWindow.hidden = YES;
            _blockWindow = nil;
        }

        UIWindow *window = nil;
        if (scene != nil) {
            window = [[UIWindow alloc] initWithWindowScene:scene];
        } else {
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
            window = [[UIWindow alloc] initWithFrame:UIScreen.mainScreen.bounds];
#pragma clang diagnostic pop
        }

        window.windowLevel = UIWindowLevelAlert + 100;
        window.backgroundColor = [UIColor colorWithRed:0.06 green:0.09 blue:0.16 alpha:1.0];
        window.rootViewController = [self viewControllerWithMessage:message];
        window.hidden = NO;
        [window makeKeyAndVisible];
        _blockWindow = window;

        NSLog(@"[Fortress] block_ui overlay shown");
    };

    if ([NSThread isMainThread]) {
        present();
    } else {
        dispatch_async(dispatch_get_main_queue(), present);
    }
}

+ (UIViewController *)viewControllerWithMessage:(NSString *)message
{
    UIViewController *controller = [[UIViewController alloc] init];
    controller.view.backgroundColor = [UIColor colorWithRed:0.06 green:0.09 blue:0.16 alpha:1.0];

    UILabel *title = [[UILabel alloc] init];
    title.translatesAutoresizingMaskIntoConstraints = NO;
    title.text = @"Security threat detected";
    title.textColor = UIColor.whiteColor;
    title.font = [UIFont boldSystemFontOfSize:22];
    title.textAlignment = NSTextAlignmentCenter;
    title.numberOfLines = 0;

    UILabel *body = [[UILabel alloc] init];
    body.translatesAutoresizingMaskIntoConstraints = NO;
    body.text = [NSString stringWithFormat:
                     @"This app has been blocked because the device appears compromised.\n\n%@",
                     message.length > 0 ? message : @"A high or critical security threat was detected."];
    body.textColor = [UIColor colorWithRed:0.89 green:0.91 blue:0.94 alpha:1.0];
    body.font = [UIFont systemFontOfSize:15];
    body.numberOfLines = 0;

    UILabel *footer = [[UILabel alloc] init];
    footer.translatesAutoresizingMaskIntoConstraints = NO;
    footer.text = @"Contact support if you believe this is an error.\n(Force-quit the app to dismiss while testing.)";
    footer.textColor = [UIColor colorWithRed:0.58 green:0.64 blue:0.72 alpha:1.0];
    footer.font = [UIFont systemFontOfSize:13];
    footer.textAlignment = NSTextAlignmentCenter;
    footer.numberOfLines = 0;

    UIScrollView *scroll = [[UIScrollView alloc] init];
    scroll.translatesAutoresizingMaskIntoConstraints = NO;

    UIStackView *stack = [[UIStackView alloc] initWithArrangedSubviews:@[ title, body, footer ]];
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 16;
    stack.alignment = UIStackViewAlignmentFill;

    [scroll addSubview:stack];
    [controller.view addSubview:scroll];

    UILayoutGuide *guide = controller.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [scroll.topAnchor constraintEqualToAnchor:guide.topAnchor],
        [scroll.leadingAnchor constraintEqualToAnchor:guide.leadingAnchor],
        [scroll.trailingAnchor constraintEqualToAnchor:guide.trailingAnchor],
        [scroll.bottomAnchor constraintEqualToAnchor:guide.bottomAnchor],

        [stack.topAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.topAnchor constant:32],
        [stack.leadingAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.leadingAnchor constant:24],
        [stack.trailingAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.trailingAnchor constant:-24],
        [stack.bottomAnchor constraintEqualToAnchor:scroll.contentLayoutGuide.bottomAnchor constant:-32],
        [stack.widthAnchor constraintEqualToAnchor:scroll.frameLayoutGuide.widthAnchor constant:-48],
    ]];

    return controller;
}

@end
