#import "ScryptPlugin.h"
#import "libscrypt.h"
#import <Cordova/CDV.h>

@implementation ScryptPlugin

@synthesize callbackId;

- (void)scrypt:(CDVInvokedUrlCommand*)command
{
    self.callbackId = command.callbackId;

    int success;
    const char* passphrase = [[command argumentAtIndex:0] UTF8String];
    const char* salt = [[command argumentAtIndex:1] UTF8String];
    uint8_t hashbuf[SCRYPT_HASH_LEN];

    // Parse options
    NSMutableDictionary* options = [command.arguments objectAtIndex:2];
    uint32_t N = [options[@"N"] unsignedShortValue] ?: SCRYPT_N;
    uint32_t r = [options[@"r"] unsignedShortValue] ?: SCRYPT_r;
    uint32_t p = [options[@"p"] unsignedShortValue] ?: SCRYPT_p;
    uint32_t dkLen = [options[@"dkLen"] unsignedShortValue] ?: 32;

    success = libscrypt_scrypt(passphrase, strlen(passphrase), salt, strlen(salt),N, r, p, hashbuf, SCRYPT_HASH_LEN);

    NSMutableString *hexResult = [NSMutableString stringWithCapacity:SCRYPT_HASH_LEN * 2];
    for(int i = 0;i < dkLen; i++ )
    {
        [hexResult appendFormat:@"%02x", hashbuf[i]];
    }
    NSString *result = [NSString stringWithString: hexResult];
    [self successWithMessage: result];
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
