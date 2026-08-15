#import "FortressEventEmitter.h"

@implementation FortressEventEmitter {
  BOOL _ready;
}

static FortressEventEmitter *_sharedEmitter = nil;

RCT_EXPORT_MODULE(FortressEventEmitter);

- (instancetype)init
{
  self = [super initWithDisabledObservation];
  if (self) {
    _sharedEmitter = self;
    _ready = NO;
  }
  return self;
}

- (NSArray<NSString *> *)supportedEvents
{
  return @[ @"onFortressThreat" ];
}

+ (BOOL)requiresMainQueueSetup
{
  return NO;
}

- (void)setCallableJSModules:(id)callableJSModules
{
  [super setCallableJSModules:callableJSModules];
  _ready = YES;
}

+ (void)emitThreat:(NSDictionary *)body
{
  if (_sharedEmitter != nil && _sharedEmitter->_ready) {
    [_sharedEmitter sendEventWithName:@"onFortressThreat" body:body];
  }
}

@end
