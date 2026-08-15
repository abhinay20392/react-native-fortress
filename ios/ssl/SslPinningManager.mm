#import "SslPinningManager.h"

#import <CommonCrypto/CommonDigest.h>
#import <Security/Security.h>

@interface FortressSslPinEntry : NSObject

@property (nonatomic, copy) NSString *host;
@property (nonatomic, copy) NSArray<NSString *> *publicKeyHashes;
@property (nonatomic, assign) BOOL includeSubdomains;

@end

@implementation FortressSslPinEntry
@end

@interface FortressSslPinningDelegate : NSObject <NSURLSessionDelegate>

@property (nonatomic, copy) NSArray<FortressSslPinEntry *> *pinEntries;

- (instancetype)initWithPinEntries:(NSArray<FortressSslPinEntry *> *)pinEntries;

@end

@implementation FortressSslPinningDelegate

- (instancetype)initWithPinEntries:(NSArray<FortressSslPinEntry *> *)pinEntries
{
    self = [super init];
    if (self) {
        _pinEntries = [pinEntries copy];
    }
    return self;
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge
  completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *_Nullable))completionHandler
{
    if (![challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
        completionHandler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
        return;
    }

    SecTrustRef serverTrust = challenge.protectionSpace.serverTrust;
    NSString *host = challenge.protectionSpace.host;

    if ([self validateServerTrust:serverTrust forHost:host]) {
        completionHandler(NSURLSessionAuthChallengeUseCredential,
                          [NSURLCredential credentialForTrust:serverTrust]);
        return;
    }

    completionHandler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
}

- (BOOL)validateServerTrust:(SecTrustRef)serverTrust forHost:(NSString *)host
{
    NSArray<FortressSslPinEntry *> *entries = [self matchingEntriesForHost:host];
    if (entries.count == 0) {
        return NO;
    }

    NSMutableSet<NSString *> *allowedPins = [NSMutableSet set];
    for (FortressSslPinEntry *entry in entries) {
        for (NSString *hash in entry.publicKeyHashes) {
            [allowedPins addObject:[SslPinningManager normalizePinHash:hash]];
        }
    }

    if (@available(iOS 15.0, *)) {
        CFArrayRef certificateChain = SecTrustCopyCertificateChain(serverTrust);
        if (certificateChain != NULL) {
            CFIndex certificateCount = CFArrayGetCount(certificateChain);
            for (CFIndex index = 0; index < certificateCount; index++) {
                SecCertificateRef certificate =
                    (SecCertificateRef)CFArrayGetValueAtIndex(certificateChain, index);
                NSString *hash = [SslPinningManager spkiHashForCertificate:certificate];
                if (hash != nil && [allowedPins containsObject:hash]) {
                    CFRelease(certificateChain);
                    return YES;
                }
            }
            CFRelease(certificateChain);
        }
    } else {
        CFIndex certificateCount = SecTrustGetCertificateCount(serverTrust);
        for (CFIndex index = 0; index < certificateCount; index++) {
            SecCertificateRef certificate = SecTrustGetCertificateAtIndex(serverTrust, index);
            NSString *hash = [SslPinningManager spkiHashForCertificate:certificate];
            if (hash != nil && [allowedPins containsObject:hash]) {
                return YES;
            }
        }
    }

    return NO;
}

- (NSArray<FortressSslPinEntry *> *)matchingEntriesForHost:(NSString *)host
{
    NSMutableArray<FortressSslPinEntry *> *matches = [NSMutableArray array];
    NSString *lowerHost = host.lowercaseString;

    for (FortressSslPinEntry *entry in self.pinEntries) {
        NSString *entryHost = entry.host.lowercaseString;
        if ([lowerHost isEqualToString:entryHost]) {
            [matches addObject:entry];
            continue;
        }

        if (entry.includeSubdomains && [lowerHost hasSuffix:[NSString stringWithFormat:@".%@", entryHost]]) {
            [matches addObject:entry];
        }
    }

    return matches;
}

@end

@implementation SslPinningManager {
    NSArray<FortressSslPinEntry *> *_pinEntries;
    BOOL _configured;
}

+ (instancetype)shared
{
    static SslPinningManager *instance;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[SslPinningManager alloc] init];
    });
    return instance;
}

- (instancetype)init
{
    self = [super init];
    if (self) {
        _pinEntries = @[];
        _configured = NO;
    }
    return self;
}

- (BOOL)configured
{
    return _configured;
}

+ (NSString *)normalizePinHash:(NSString *)hash
{
    if ([hash hasPrefix:@"sha256/"]) {
        return [hash substringFromIndex:7];
    }
    return hash;
}

+ (NSString *)spkiHashForCertificate:(SecCertificateRef)certificate
{
    SecKeyRef publicKey = SecCertificateCopyKey(certificate);
    if (publicKey == NULL) {
        return nil;
    }

    CFErrorRef error = NULL;
    CFDataRef publicKeyDataRef = SecKeyCopyExternalRepresentation(publicKey, &error);
    CFRelease(publicKey);

    if (publicKeyDataRef == NULL) {
        return nil;
    }

    NSData *publicKeyData = (__bridge_transfer NSData *)publicKeyDataRef;
    NSData *spkiData = [self spkiDataFromPublicKeyData:publicKeyData];
    if (spkiData == nil) {
        return nil;
    }

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(spkiData.bytes, (CC_LONG)spkiData.length, digest);
    NSData *hashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return [hashData base64EncodedStringWithOptions:0];
}

+ (NSData *)spkiDataFromPublicKeyData:(NSData *)publicKeyData
{
    if (publicKeyData.length == 65 && ((const uint8_t *)publicKeyData.bytes)[0] == 0x04) {
        static const uint8_t ec256Header[] = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        };

        NSMutableData *spki = [NSMutableData dataWithBytes:ec256Header length:sizeof(ec256Header)];
        [spki appendData:publicKeyData];
        return spki;
    }

    if (publicKeyData.length == 256) {
        static const uint8_t rsa2048Header[] = {
            0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
            0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
        };

        NSMutableData *spki = [NSMutableData dataWithBytes:rsa2048Header length:sizeof(rsa2048Header)];
        [spki appendData:publicKeyData];
        return spki;
    }

    return publicKeyData;
}

- (void)configurePins:(NSArray *)pins
{
    NSMutableArray<FortressSslPinEntry *> *entries = [NSMutableArray array];

    for (id item in pins) {
        if (![item isKindOfClass:[NSDictionary class]]) {
            continue;
        }

        NSDictionary *pinMap = (NSDictionary *)item;
        NSString *host = [pinMap[@"host"] isKindOfClass:[NSString class]] ? pinMap[@"host"] : nil;
        if (host.length == 0) {
            continue;
        }

        NSArray *hashes = [pinMap[@"publicKeyHashes"] isKindOfClass:[NSArray class]]
                              ? pinMap[@"publicKeyHashes"]
                              : nil;
        NSMutableArray<NSString *> *normalizedHashes = [NSMutableArray array];
        for (id hashValue in hashes) {
            if ([hashValue isKindOfClass:[NSString class]] && [(NSString *)hashValue length] > 0) {
                [normalizedHashes addObject:[SslPinningManager normalizePinHash:(NSString *)hashValue]];
            }
        }

        if (normalizedHashes.count == 0) {
            continue;
        }

        FortressSslPinEntry *entry = [[FortressSslPinEntry alloc] init];
        entry.host = host;
        entry.publicKeyHashes = normalizedHashes;
        entry.includeSubdomains =
            [pinMap[@"includeSubdomains"] isKindOfClass:[NSNumber class]] &&
            [pinMap[@"includeSubdomains"] boolValue];
        [entries addObject:entry];
    }

    _pinEntries = [entries copy];
    _configured = _pinEntries.count > 0;
}

- (void)performPinnedRequestWithURL:(NSString *)url
                            resolve:(void (^)(NSDictionary *result))resolve
                             reject:(void (^)(NSString *code, NSString *message, NSError *_Nullable error))reject
                         emitThreat:(void (^)(NSDictionary *threat))emitThreat
{
    if (!_configured) {
        reject(@"E_SSL_PINNING", @"SSL pinning is not configured. Call configureSslPinning first.", nil);
        return;
    }

    NSURL *requestURL = [NSURL URLWithString:url];
    if (requestURL == nil) {
        reject(@"E_SSL_REQUEST", @"Invalid URL", nil);
        return;
    }

    FortressSslPinningDelegate *delegate = [[FortressSslPinningDelegate alloc] initWithPinEntries:_pinEntries];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                        delegate:delegate
                                                   delegateQueue:nil];

    NSURLSessionDataTask *task =
        [session dataTaskWithURL:requestURL
               completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                   if (error != nil) {
                       NSString *detail = error.localizedDescription ?: @"SSL pinning validation failed";
                       NSString *message = [NSString stringWithFormat:
                           @"Pinned request failed for %@: %@. "
                            "Check publicKeyHashes match the cert the app sees (CDN/edge), "
                            "and include a backup pin before certificate rotation.",
                           url, detail];
                       emitThreat(@{
                           @"type": @"ssl_pin_failure",
                           @"severity": @"high",
                           @"message": message,
                           @"platform": @"ios",
                           @"timestamp": @([[NSDate date] timeIntervalSince1970] * 1000),
                       });
                       reject(@"E_SSL_PIN_FAILURE", message, error);
                       [session finishTasksAndInvalidate];
                       return;
                   }

                   NSHTTPURLResponse *httpResponse = (NSHTTPURLResponse *)response;
                   NSString *body = data != nil ? [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] : @"";
                   resolve(@{
                       @"ok": @(httpResponse.statusCode >= 200 && httpResponse.statusCode < 300),
                       @"status": @(httpResponse.statusCode),
                       @"url": url,
                       @"body": body ?: @"",
                       @"pinned": @YES,
                       @"sslPinVerified": @YES,
                   });
                   [session finishTasksAndInvalidate];
               }];

    [task resume];
}

@end
