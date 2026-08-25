#import "SslPinningManager.h"

#import "ThreatScoring.h"
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
    // Require a valid system trust evaluation before accepting a pin match.
    CFErrorRef trustError = NULL;
    if (!SecTrustEvaluateWithError(serverTrust, &trustError)) {
        if (trustError != NULL) {
            CFRelease(trustError);
        }
        return NO;
    }

    NSArray<FortressSslPinEntry *> *entries = [self matchingEntriesForHost:host];
    if (entries.count == 0) {
        return NO;
    }

    NSMutableArray<NSString *> *allowedPins = [NSMutableArray array];
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
                if (hash != nil &&
                    [FortressThreatScoring constantTimeContains:hash in:allowedPins]) {
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
            if (hash != nil && [FortressThreatScoring constantTimeContains:hash in:allowedPins]) {
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

    NSData *spkiData = [self spkiDataFromPublicKey:publicKey];
    CFRelease(publicKey);

    if (spkiData == nil) {
        return nil;
    }

    uint8_t digest[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256(spkiData.bytes, (CC_LONG)spkiData.length, digest);
    NSData *hashData = [NSData dataWithBytes:digest length:CC_SHA256_DIGEST_LENGTH];
    return [hashData base64EncodedStringWithOptions:0];
}

/**
 * Build SubjectPublicKeyInfo DER for common EC / RSA sizes.
 * Headers match OkHttp / TrustKit SPKI pin format (sha256 of SPKI).
 */
+ (nullable NSData *)spkiDataFromPublicKey:(SecKeyRef)publicKey
{
    CFErrorRef error = NULL;
    CFDataRef publicKeyDataRef = SecKeyCopyExternalRepresentation(publicKey, &error);
    if (publicKeyDataRef == NULL) {
        if (error != NULL) {
            CFRelease(error);
        }
        return nil;
    }

    NSData *publicKeyData = (__bridge_transfer NSData *)publicKeyDataRef;
    NSDictionary *attributes = CFBridgingRelease(SecKeyCopyAttributes(publicKey));
    NSString *keyType = attributes[(__bridge id)kSecAttrKeyType];
    NSNumber *sizeBits = attributes[(__bridge id)kSecAttrKeySizeInBits];

    const uint8_t *header = NULL;
    size_t headerLength = 0;

    BOOL isEC =
        [keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeECSECPrimeRandom] ||
        [keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeEC];

    if (isEC) {
        switch (sizeBits.integerValue) {
            case 256: {
                // secp256r1 / P-256
                static const uint8_t ec256Header[] = {
                    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
                };
                header = ec256Header;
                headerLength = sizeof(ec256Header);
                break;
            }
            case 384: {
                // secp384r1 / P-384
                static const uint8_t ec384Header[] = {
                    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00
                };
                header = ec384Header;
                headerLength = sizeof(ec384Header);
                break;
            }
            case 521: {
                // secp521r1 / P-521
                static const uint8_t ec521Header[] = {
                    0x30, 0x81, 0x9b, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, 0x03, 0x81, 0x86, 0x00
                };
                header = ec521Header;
                headerLength = sizeof(ec521Header);
                break;
            }
            default:
                break;
        }
    } else if ([keyType isEqualToString:(__bridge NSString *)kSecAttrKeyTypeRSA]) {
        switch (sizeBits.integerValue) {
            case 2048: {
                static const uint8_t rsa2048Header[] = {
                    0x30, 0x82, 0x01, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0f, 0x00
                };
                header = rsa2048Header;
                headerLength = sizeof(rsa2048Header);
                break;
            }
            case 3072: {
                static const uint8_t rsa3072Header[] = {
                    0x30, 0x82, 0x01, 0xa2, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x8f, 0x00
                };
                header = rsa3072Header;
                headerLength = sizeof(rsa3072Header);
                break;
            }
            case 4096: {
                static const uint8_t rsa4096Header[] = {
                    0x30, 0x82, 0x02, 0x22, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
                    0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x02, 0x0f, 0x00
                };
                header = rsa4096Header;
                headerLength = sizeof(rsa4096Header);
                break;
            }
            default:
                break;
        }
    }

    if (header != NULL && headerLength > 0) {
        NSMutableData *spki = [NSMutableData dataWithBytes:header length:headerLength];
        [spki appendData:publicKeyData];
        return spki;
    }

    // Fallback: some keys already return SPKI-shaped DER.
    if (publicKeyData.length > 2 && ((const uint8_t *)publicKeyData.bytes)[0] == 0x30) {
        return publicKeyData;
    }

    // Legacy heuristic for older paths that returned raw EC point / RSA modulus only.
    if (publicKeyData.length == 65 && ((const uint8_t *)publicKeyData.bytes)[0] == 0x04) {
        static const uint8_t ec256Header[] = {
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00
        };
        NSMutableData *spki = [NSMutableData dataWithBytes:ec256Header length:sizeof(ec256Header)];
        [spki appendData:publicKeyData];
        return spki;
    }

    return nil;
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

- (NSDictionary *)pinningStatus
{
    NSMutableArray *hosts = [NSMutableArray array];
    for (FortressSslPinEntry *entry in _pinEntries) {
        [hosts addObject:@{
            @"host": entry.host ?: @"",
            @"pinCount": @(entry.publicKeyHashes.count),
            @"includeSubdomains": @(entry.includeSubdomains),
        }];
    }

    return @{
        @"configured": @(_configured),
        @"hosts": hosts,
        @"coversGlobalFetch": @NO,
        @"platformNote":
            @"iOS: only Fortress.fetchPinned is certificate-pinned. Global fetch()/XHR are not intercepted.",
    };
}

+ (NSError *)sslErrorWithCode:(NSString *)code
                      message:(NSString *)message
                       reason:(NSString *)reason
                          url:(nullable NSString *)url
                       method:(nullable NSString *)method
{
    NSMutableDictionary *userInfo = [@{
        NSLocalizedDescriptionKey: message,
        @"reason": reason,
    } mutableCopy];
    if (url.length > 0) {
        userInfo[@"url"] = url;
    }
    if (method.length > 0) {
        userInfo[@"method"] = method;
    }
    userInfo[@"code"] = code;
    return [NSError errorWithDomain:@"com.fortress.ssl" code:1 userInfo:userInfo];
}

- (void)performPinnedRequestWithOptions:(NSDictionary *)options
                                resolve:(void (^)(NSDictionary *result))resolve
                                 reject:(void (^)(NSString *code, NSString *message, NSError *_Nullable error))reject
                             emitThreat:(void (^)(NSDictionary *threat))emitThreat
{
    if (!_configured) {
        NSString *message = @"SSL pinning is not configured. Call configureSslPinning first.";
        reject(@"E_SSL_PINNING",
               message,
               [SslPinningManager sslErrorWithCode:@"E_SSL_PINNING"
                                           message:message
                                            reason:@"not_configured"
                                               url:nil
                                            method:nil]);
        return;
    }

    NSString *url = [options[@"url"] isKindOfClass:[NSString class]] ? options[@"url"] : nil;
    url = [url stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (url.length == 0) {
        NSString *message = @"Pinned request requires a non-empty url";
        reject(@"E_SSL_REQUEST",
               message,
               [SslPinningManager sslErrorWithCode:@"E_SSL_REQUEST"
                                           message:message
                                            reason:@"invalid_url"
                                               url:nil
                                            method:nil]);
        return;
    }

    NSString *method = [options[@"method"] isKindOfClass:[NSString class]] ? options[@"method"] : @"GET";
    method = [[method stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]] uppercaseString];
    if (method.length == 0) {
        method = @"GET";
    }
    NSSet<NSString *> *allowed =
        [NSSet setWithArray:@[ @"GET", @"POST", @"PUT", @"PATCH", @"DELETE", @"HEAD" ]];
    if (![allowed containsObject:method]) {
        NSString *message = [NSString stringWithFormat:@"Unsupported HTTP method: %@", method];
        reject(@"E_SSL_REQUEST",
               message,
               [SslPinningManager sslErrorWithCode:@"E_SSL_REQUEST"
                                           message:message
                                            reason:@"unsupported_method"
                                               url:url
                                            method:method]);
        return;
    }

    NSURL *requestURL = [NSURL URLWithString:url];
    if (requestURL == nil) {
        NSString *message = @"Invalid URL";
        reject(@"E_SSL_REQUEST",
               message,
               [SslPinningManager sslErrorWithCode:@"E_SSL_REQUEST"
                                           message:message
                                            reason:@"invalid_url"
                                               url:url
                                            method:method]);
        return;
    }

    NSMutableURLRequest *request = [NSMutableURLRequest requestWithURL:requestURL];
    request.HTTPMethod = method;

    id headers = options[@"headers"];
    if ([headers isKindOfClass:[NSDictionary class]]) {
        [(NSDictionary *)headers enumerateKeysAndObjectsUsingBlock:^(id key, id value, BOOL *stop) {
            if ([key isKindOfClass:[NSString class]] && [value isKindOfClass:[NSString class]]) {
                [request setValue:(NSString *)value forHTTPHeaderField:(NSString *)key];
            }
        }];
    }

    if (![method isEqualToString:@"GET"] && ![method isEqualToString:@"HEAD"]) {
        id body = options[@"body"];
        if ([body isKindOfClass:[NSString class]]) {
            request.HTTPBody = [(NSString *)body dataUsingEncoding:NSUTF8StringEncoding];
        }
    }

    FortressSslPinningDelegate *delegate = [[FortressSslPinningDelegate alloc] initWithPinEntries:_pinEntries];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:[NSURLSessionConfiguration ephemeralSessionConfiguration]
                                                          delegate:delegate
                                                     delegateQueue:nil];

    NSURLSessionDataTask *task =
        [session dataTaskWithRequest:request
                   completionHandler:^(NSData *data, NSURLResponse *response, NSError *error) {
                       if (error != nil) {
                           BOOL pinFailure =
                               [error.domain isEqualToString:NSURLErrorDomain] &&
                               (error.code == NSURLErrorCancelled ||
                                error.code == NSURLErrorSecureConnectionFailed ||
                                error.code == NSURLErrorServerCertificateUntrusted ||
                                error.code == NSURLErrorClientCertificateRejected);

                           NSString *reason = pinFailure ? @"pin_mismatch" : @"network";
                           NSString *code = pinFailure ? @"E_SSL_PIN_FAILURE" : @"E_SSL_REQUEST";
                           NSString *detail = error.localizedDescription ?: @"SSL pinning validation failed";
                           NSString *message = pinFailure
                               ? [NSString stringWithFormat:
                                     @"Pinned request failed for %@: %@. "
                                      "Check publicKeyHashes match the cert the app sees (CDN/edge), "
                                      "and include a backup pin before certificate rotation.",
                                     url, detail]
                               : [NSString stringWithFormat:@"Pinned request failed for %@: %@", url, detail];

                           if (pinFailure) {
                               emitThreat(@{
                                   @"type": @"ssl_pin_failure",
                                   @"severity": @"high",
                                   @"message": message,
                                   @"platform": @"ios",
                                   @"timestamp": @([[NSDate date] timeIntervalSince1970] * 1000),
                                   @"code": @"SSL_PIN_FAILURE",
                                   @"detector": @"SslPinningManager",
                                   @"evidence": @{
                                       @"url": url,
                                       @"method": method,
                                       @"reason": reason,
                                   },
                               });
                           }

                           NSError *structured = [SslPinningManager sslErrorWithCode:code
                                                                             message:message
                                                                              reason:reason
                                                                                 url:url
                                                                              method:method];
                           reject(code, message, structured);
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
                           @"method": method,
                       });
                       [session finishTasksAndInvalidate];
                   }];

    [task resume];
}

@end
