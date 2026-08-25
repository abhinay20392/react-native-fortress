#import "TamperDetector.h"

#import "FortressThreatResult.h"
#import "ThreatScoring.h"
#import <TargetConditionals.h>
#import <mach-o/dyld.h>
#import <sys/sysctl.h>
#import <unistd.h>

@implementation TamperDetector

+ (NSArray<NSString *> *)fridaSignatures
{
    return @[ @"frida-gadget", @"frida-agent", @"gum-js", @"linjector", @"frida" ];
}

+ (NSArray<NSString *> *)hookSignatures
{
    return @[ @"MobileSubstrate", @"Substrate", @"Substitute", @"MSHook", @"cycript", @"TweakInject" ];
}

+ (NSArray<FortressThreatResult *> *)runChecks
{
    NSMutableArray<FortressThreatResult *> *threats = [NSMutableArray array];

    FortressThreatResult *fridaMaps = [self checkFridaInMaps];
    if (fridaMaps != nil) {
        [threats addObject:fridaMaps];
    }

    FortressThreatResult *dyldInsert = [self checkDyldInsertLibraries];
    if (dyldInsert != nil) {
        [threats addObject:dyldInsert];
    }

    FortressThreatResult *debugger = [self checkDebuggerAttached];
    if (debugger != nil) {
        [threats addObject:debugger];
    }

    FortressThreatResult *hooks = [self checkHookingLibraries];
    if (hooks != nil) {
        [threats addObject:hooks];
    }

    return threats;
}

+ (BOOL)isCompromisedWithThreats:(NSArray<FortressThreatResult *> *)threats
{
    return [FortressThreatScoring isCompromisedWithThreats:threats];
}

+ (FortressThreatResult *)makeThreatWithType:(NSString *)type
                                    severity:(NSString *)severity
                                     message:(NSString *)message
{
    FortressThreatResult *threat = [[FortressThreatResult alloc] init];
    threat.type = type;
    threat.severity = severity;
    threat.message = message;
    return threat;
}

+ (BOOL)imageName:(NSString *)name matchesSignatures:(NSArray<NSString *> *)signatures
{
    NSString *lastComponent = name.lastPathComponent ?: name;
    for (NSString *needle in signatures) {
        if ([lastComponent rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
        NSString *pathNeedle = [NSString stringWithFormat:@"/%@", needle];
        if ([name rangeOfString:pathNeedle options:NSCaseInsensitiveSearch].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

+ (FortressThreatResult *)checkFridaInMaps
{
    NSMutableArray<NSString *> *found = [NSMutableArray array];
    uint32_t imageCount = _dyld_image_count();

    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName == NULL) {
            continue;
        }

        NSString *name = [NSString stringWithUTF8String:imageName];
        if ([self imageName:name matchesSignatures:[self fridaSignatures]]) {
            [found addObject:name];
        }
    }

    if (found.count == 0) {
        return nil;
    }

    return [self makeThreatWithType:@"frida"
                           severity:@"critical"
                            message:[NSString stringWithFormat:@"Frida indicators in loaded images: %@",
                                                               [found componentsJoinedByString:@", "]]];
}

+ (FortressThreatResult *)checkDyldInsertLibraries
{
#if TARGET_OS_SIMULATOR
    // Simulator / Xcode tooling may inject libraries; not a reliable device signal.
    return nil;
#else
    const char *env = getenv("DYLD_INSERT_LIBRARIES");
    if (env == NULL || strlen(env) == 0) {
        return nil;
    }

    return [self makeThreatWithType:@"hooking"
                           severity:@"high"
                            message:[NSString stringWithFormat:@"DYLD_INSERT_LIBRARIES is set: %s", env]];
#endif
}

+ (FortressThreatResult *)checkDebuggerAttached
{
#if TARGET_OS_SIMULATOR
    // Simulator debug sessions are the normal Xcode workflow — skip to avoid false positives.
    return nil;
#else
    struct kinfo_proc info;
    size_t size = sizeof(info);
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid()};

    if (sysctl(mib, 4, &info, &size, NULL, 0) != 0) {
        return nil;
    }

    if ((info.kp_proc.p_flag & P_TRACED) == 0) {
        return nil;
    }

    return [self makeThreatWithType:@"debugger"
                           severity:@"high"
                            message:@"Process is being traced (P_TRACED via sysctl)"];
#endif
}

+ (FortressThreatResult *)checkHookingLibraries
{
    NSMutableArray<NSString *> *found = [NSMutableArray array];
    uint32_t imageCount = _dyld_image_count();

    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName == NULL) {
            continue;
        }

        NSString *name = [NSString stringWithUTF8String:imageName];
        if ([self imageName:name matchesSignatures:[self hookSignatures]]) {
            [found addObject:name];
        }
    }

    if (found.count == 0) {
        return nil;
    }

    return [self makeThreatWithType:@"hooking"
                           severity:@"high"
                            message:[NSString stringWithFormat:@"Hooking libraries loaded: %@",
                                                               [found componentsJoinedByString:@", "]]];
}

@end
