#import <Foundation/Foundation.h>
#import "ScryptPlugin.h"
#import "libscrypt.h"
#import <Cordova/CDV.h>

@implementation ScryptPlugin

@synthesize callbackId;

- (void)scrypt:(CDVInvokedUrlCommand*)command
{

    int i, success;
    size_t saltLength;
    const uint8_t *parsedSalt;
    uint8_t *buffer = NULL;
    const char* passphrase = [[command argumentAtIndex:0] UTF8String];
    id salt = [command argumentAtIndex:1];

    if ([salt isKindOfClass:[NSString class]]) {
        parsedSalt = (const uint8_t *)[salt UTF8String];
        saltLength = (size_t) [salt length];
    } else if ([salt isKindOfClass:[NSArray class]]) {
        saltLength = (int) [salt count];
        buffer = malloc(sizeof(uint8_t) * saltLength);

        for (i = 0; i < saltLength; ++i) {
            buffer[i] = (uint8_t)[[salt objectAtIndex:i] integerValue];
        }
        parsedSalt = buffer;
    }

    // Parse options
    NSMutableDictionary* options = [command.arguments objectAtIndex:2];
    uint64_t N = [options[@"N"] unsignedLongValue] ?: SCRYPT_N;
    uint32_t r = [options[@"r"] unsignedShortValue] ?: SCRYPT_r;
    uint32_t p = [options[@"p"] unsignedShortValue] ?: SCRYPT_p;
    uint32_t dkLen = [options[@"dkLen"] unsignedShortValue] ?: 32;

    uint8_t hashbuf[dkLen];
    self.callbackId = command.callbackId;

    @try {
        success = libscrypt_scrypt((uint8_t *)passphrase, strlen(passphrase), parsedSalt, saltLength, N, r, p, hashbuf, dkLen);
    }
    @catch (NSException * e) {
        [self failWithMessage: [NSString stringWithFormat:@"%@", e] withError: nil];
    }

    if (success!=0) {
        [self failWithMessage: @"Failure in scrypt" withError: nil];
    }


    // Hexify
    NSMutableString *hexResult = [NSMutableString stringWithCapacity:dkLen * 2];
    for(i = 0;i < dkLen; i++ )
    {
        [hexResult appendFormat:@"%02x", hashbuf[i]];
    }
    NSString *result = [NSString stringWithString: hexResult];
    [self successWithMessage: result];

    free(buffer);
}

-(void)successWithMessage:(NSString *)message
{
    if (self.callbackId != nil)
    {
        CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsString:message];
        [self.commandDelegate sendPluginResult:commandResult callbackId:self.callbackId];
    }
}

-(void)failWithMessage:(NSString *)message withError:(NSError *)error
{
    NSString        *errorMessage = (error) ? [NSString stringWithFormat:@"%@ - %@", message, [error localizedDescription]] : message;
    CDVPluginResult *commandResult = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR messageAsString:errorMessage];

    [self.commandDelegate sendPluginResult:commandResult callbackId:self.callbackId];
}

@end
