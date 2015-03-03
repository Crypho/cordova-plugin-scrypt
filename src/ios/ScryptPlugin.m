#import "ScryptPlugin.h"
#import "libscrypt.h"
#import <Cordova/CDV.h>

@implementation ScryptPlugin

/* log a message */
- (void)scrypt:(CDVInvokedUrlCommand*)command
{
    id message = [command argumentAtIndex:0];
    const char* passphrase = [message UTF8String];
    NSMutableDictionary* options = [command.arguments objectAtIndex:1];
    NSLog(@"%s", passphrase);
    NSLog(@"%@", options);
    char* res;
    libscrypt_hash(res, passphrase, SCRYPT_N, SCRYPT_r, SCRYPT_p);
    NSLog(@"%@", message);

}

@end
