#import "JailbreakDetector.h"

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

+ (NSArray<NSString *> *)suspiciousPaths
{
    return @[
        @"/Applications/Cydia.app",
        @"/Applications/Sileo.app",
        @"/Applications/Zebra.app",
        @"/Library/MobileSubstrate/MobileSubstrate.dylib",
        @"/bin/bash",
        @"/usr/sbin/sshd",
        @"/etc/apt",
        @"/private/var/lib/apt/",
        @"/private/var/lib/cydia",
        @"/private/var/stash",
        @"/usr/libexec/sftp-server",
        @"/usr/bin/ssh",
        @"/private/var/mobile/Library/SBSettings",
        @"/var/jb",
        @"/var/binpack",
    ];
}

+ (NSArray<NSString *> *)suspiciousDylibs
{
    return @[
        @"Substrate",
        @"Substitute",
        @"frida",
        @"cycript",
        @"SSLKillSwitch",
        @"MobileSubstrate",
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

    FortressThreatResult *statThreat = [self checkRestrictedPathStat];
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
    if (threats.count == 0) {
        return NO;
    }

    for (FortressThreatResult *threat in threats) {
        if ([threat.severity isEqualToString:@"high"] ||
            [threat.severity isEqualToString:@"critical"]) {
            return YES;
        }
    }

    return threats.count >= 2;
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
        for (NSString *needle in [self suspiciousDylibs]) {
            if ([name rangeOfString:needle options:NSCaseInsensitiveSearch].location != NSNotFound) {
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

+ (FortressThreatResult *)checkRestrictedPathStat
{
    struct stat statInfo;
    if (stat("/private/jailbreak.txt", &statInfo) == 0) {
        return [self makeThreatWithType:@"jailbreak"
                               severity:@"medium"
                                message:@"Restricted path /private/jailbreak.txt is accessible"];
    }

    return nil;
}

+ (FortressThreatResult *)checkCydiaUrlScheme
{
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
}

@end
