#import "JailbreakDetector.h"

#import "FortressThreatResult.h"
#import "ThreatScoring.h"
#import <TargetConditionals.h>
#import <UIKit/UIKit.h>
#import <mach-o/dyld.h>
#import <sys/stat.h>
#import <unistd.h>

@implementation FortressThreatResult

- (NSDictionary *)toDictionary
{
    return @{
        @"type": self.type ?: @"",
        @"severity": self.severity ?: @"",
        @"message": self.message ?: @"",
        @"platform": @"ios",
        @"timestamp": @([[NSDate date] timeIntervalSince1970] * 1000),
    };
}

@end

@implementation JailbreakDetector

/// Paths that indicate a jailbreak on real devices and are safe to check on Simulator.
+ (NSArray<NSString *> *)jailbreakSpecificPaths
{
    return @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/private/var/lib/apt/",
        @"/private/var/lib/cydia",
        @"/private/var/stash",
        @"/private/var/mobile/Library/SBSettings",
        @"/var/jb",
        @"/var/binpack",
        @"/usr/libexec/sftp-server",
    ];
}

/// Unix tooling paths that often exist on the Simulator (macOS host) and cause false positives.
+ (NSArray<NSString *> *)deviceOnlyUnixPaths
{
    return @[
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/usr/bin/ssh",
    ];
}

+ (NSArray<NSString *> *)suspiciousPaths
{
    NSMutableArray<NSString *> *paths = [[self jailbreakSpecificPaths] mutableCopy];
#if !TARGET_OS_SIMULATOR
    [paths addObjectsFromArray:[self deviceOnlyUnixPaths]];
#endif
    return paths;
}

+ (NSArray<NSString *> *)suspiciousDylibs
{
    return @[
        @"MobileSubstrate",
        @"Substrate",
        @"Substitute",
        @"frida-gadget",
        @"frida-agent",
        @"cycript",
        @"SSLKillSwitch",
        @"TweakInject",
    ];
}

+ (NSArray<FortressThreatResult *> *)runChecks
{
    NSMutableArray<FortressThreatResult *> *threats = [NSMutableArray array];

    FortressThreatResult *pathThreat = [self checkSuspiciousPaths];
    if (pathThreat != nil) {
        [threats addObject:pathThreat];
    }

    FortressThreatResult *dylibThreat = [self checkSuspiciousDylibs];
    if (dylibThreat != nil) {
        [threats addObject:dylibThreat];
    }

    FortressThreatResult *forkThreat = [self checkForkViolation];
    if (forkThreat != nil) {
        [threats addObject:forkThreat];
    }

    FortressThreatResult *statThreat = [self checkRestrictedPathWrite];
    if (statThreat != nil) {
        [threats addObject:statThreat];
    }

    FortressThreatResult *schemeThreat = [self checkCydiaUrlScheme];
    if (schemeThreat != nil) {
        [threats addObject:schemeThreat];
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

+ (FortressThreatResult *)checkSuspiciousPaths
{
    NSMutableArray<NSString *> *found = [NSMutableArray array];

    for (NSString *path in [self suspiciousPaths]) {
        if ([[NSFileManager defaultManager] fileExistsAtPath:path]) {
            [found addObject:path];
        }
    }

    if (found.count == 0) {
        return nil;
    }

    return [self makeThreatWithType:@"jailbreak"
                           severity:@"high"
                            message:[NSString stringWithFormat:@"Jailbreak paths found: %@",
                                                               [found componentsJoinedByString:@", "]]];
}

+ (FortressThreatResult *)checkSuspiciousDylibs
{
    NSMutableArray<NSString *> *found = [NSMutableArray array];
    uint32_t imageCount = _dyld_image_count();

    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (imageName == NULL) {
            continue;
        }

        NSString *name = [NSString stringWithUTF8String:imageName];
        NSString *lastComponent = name.lastPathComponent ?: name;
        for (NSString *needle in [self suspiciousDylibs]) {
            if ([lastComponent rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound ||
                [name rangeOfString:[NSString stringWithFormat:@"/%@", needle]
                            options:NSCaseInsensitiveSearch]
                        .location != NSNotFound) {
                [found addObject:name];
                break;
            }
        }
    }

    if (found.count == 0) {
        return nil;
    }

    return [self makeThreatWithType:@"jailbreak"
                           severity:@"high"
                            message:[NSString stringWithFormat:@"Suspicious dylibs loaded: %@",
                                                               [found componentsJoinedByString:@", "]]];
}

+ (FortressThreatResult *)checkForkViolation
{
#if TARGET_OS_SIMULATOR
    return nil;
#else
    pid_t pid = fork();
    if (pid < 0) {
        return nil;
    }

    if (pid == 0) {
        _exit(0);
    }

    return [self makeThreatWithType:@"jailbreak"
                           severity:@"high"
                            message:@"fork() succeeded — sandbox violation"];
#endif
}

+ (FortressThreatResult *)checkRestrictedPathWrite
{
#if TARGET_OS_SIMULATOR
    return nil;
#else
    NSString *probePath = @"/private/fortress_jb_probe.txt";
    NSError *error = nil;
    BOOL wrote = [@"fortress" writeToFile:probePath
                               atomically:YES
                                 encoding:NSUTF8StringEncoding
                                    error:&error];
    if (!wrote) {
        return nil;
    }

    [[NSFileManager defaultManager] removeItemAtPath:probePath error:nil];
    return [self makeThreatWithType:@"jailbreak"
                           severity:@"high"
                            message:@"Wrote outside the app sandbox (/private) — jailbreak indicator"];
#endif
}

+ (FortressThreatResult *)checkCydiaUrlScheme
{
#if TARGET_OS_SIMULATOR
    return nil;
#else
    NSURL *url = [NSURL URLWithString:@"cydia://package/com.example.package"];
    if (url == nil) {
        return nil;
    }

    if ([[UIApplication sharedApplication] canOpenURL:url]) {
        return [self makeThreatWithType:@"jailbreak"
                               severity:@"low"
                                message:@"cydia:// URL scheme is available"];
    }

    return nil;
#endif
}

@end
