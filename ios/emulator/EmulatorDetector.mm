#import "EmulatorDetector.h"

#import <TargetConditionals.h>
#import <sys/sysctl.h>
#import <sys/utsname.h>
#import <string.h>
#import <stdlib.h>

@implementation EmulatorDetector

+ (NSArray<FortressThreatResult *> *)runChecks
{
    NSMutableArray<NSString *> *signals = [NSMutableArray array];

#if TARGET_OS_SIMULATOR
    [signals addObject:@"TARGET_OS_SIMULATOR=1"];
#endif

    NSString *hwMachine = [self hardwareMachine];
    if (hwMachine.length > 0) {
        NSString *lower = hwMachine.lowercaseString;
        if ([lower containsString:@"x86"] || [lower containsString:@"i386"]) {
            [signals addObject:[NSString stringWithFormat:@"hw.machine=%@", hwMachine]];
        }
    }

    struct utsname systemInfo;
    if (uname(&systemInfo) == 0) {
        NSString *machine = [NSString stringWithCString:systemInfo.machine encoding:NSUTF8StringEncoding];
        NSString *lower = machine.lowercaseString;
        if ([lower containsString:@"x86"] || [lower containsString:@"i386"]) {
            NSString *label = [NSString stringWithFormat:@"uname.machine=%@", machine];
            if (![signals containsObject:label]) {
                [signals addObject:label];
            }
        }
    }

    const char *simDevice = getenv("SIMULATOR_DEVICE_NAME");
    if (simDevice != NULL && strlen(simDevice) > 0) {
        [signals addObject:[NSString stringWithFormat:@"SIMULATOR_DEVICE_NAME=%s", simDevice]];
    }

    if (signals.count == 0) {
        return @[];
    }

    // Deduplicate while preserving order.
    NSMutableArray<NSString *> *unique = [NSMutableArray array];
    for (NSString *signal in signals) {
        if (![unique containsObject:signal]) {
            [unique addObject:signal];
        }
    }

    FortressThreatResult *threat = [[FortressThreatResult alloc] init];
    threat.type = @"emulator";
    threat.severity = @"medium";
    threat.message = [NSString stringWithFormat:@"Emulator / Simulator indicators: %@",
                                                [unique componentsJoinedByString:@"; "]];
    return @[ threat ];
}

+ (nullable NSString *)hardwareMachine
{
    size_t size = 0;
    if (sysctlbyname("hw.machine", NULL, &size, NULL, 0) != 0 || size == 0) {
        return nil;
    }

    char *machine = (char *)malloc(size);
    if (machine == NULL) {
        return nil;
    }

    if (sysctlbyname("hw.machine", machine, &size, NULL, 0) != 0) {
        free(machine);
        return nil;
    }

    NSString *value = [NSString stringWithCString:machine encoding:NSUTF8StringEncoding];
    free(machine);
    return value;
}

@end
