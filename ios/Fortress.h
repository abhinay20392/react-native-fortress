#import <FortressSpec/FortressSpec.h>

#import "ThreatOrchestrator.h"

@interface Fortress : NSObject <NativeFortressSpec>

@property (nonatomic, strong) ThreatOrchestrator *orchestrator;

@end
