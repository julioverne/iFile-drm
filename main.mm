#import <CommonCrypto/CommonCrypto.h>

OBJC_EXTERN CFStringRef MGCopyAnswer(CFStringRef key) WEAK_IMPORT_ATTRIBUTE;

@interface NSUserDefaults ()
- (void)setObject:(id)value forKey:(NSString *)key inDomain:(NSString *)domain;
@end

@implementation NSData (aes)
- (NSString *)hexString
{
    const unsigned char *dataBuffer = (const unsigned char *)[self bytes];
    if (!dataBuffer)
    {
	return [NSString string];
    }
    NSUInteger		dataLength  = [self length];
    NSMutableString	*hexString  = [NSMutableString stringWithCapacity:(dataLength * 2)];
    for (int i = 0; i < dataLength; ++i)
    {
	[hexString appendFormat:@"%02x", (unsigned int)dataBuffer[i]];
    }
    return [NSString stringWithString:hexString];
}
- (NSData *)AES128:(CCOperation)operation key:(NSString *)key iv:(NSString *)iv
{		  //CCOperation: kCCDecrypt/kCCEncrypt
    char keyPtr[kCCKeySizeAES128 + 1];
    bzero(keyPtr, sizeof(keyPtr));
    [key getCString:keyPtr maxLength:sizeof(keyPtr) encoding:NSUTF8StringEncoding];
    char ivPtr[kCCBlockSizeAES128 + 1];
    bzero(ivPtr, sizeof(ivPtr));
    if (iv) {
	[iv getCString:ivPtr maxLength:sizeof(ivPtr) encoding:NSUTF8StringEncoding];
    }
    NSUInteger dataLength = [self length];
    size_t bufferSize = dataLength + kCCBlockSizeAES128;
    void *buffer = malloc(bufferSize);
    size_t numBytesEncrypted = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
					  kCCAlgorithmAES128,
					  kCCOptionPKCS7Padding | kCCOptionECBMode,
					  keyPtr,
					  kCCBlockSizeAES128,
					  ivPtr,
					  [self bytes],
					  dataLength,
					  buffer,
					  bufferSize,
					  &numBytesEncrypted);
    if (cryptStatus == kCCSuccess) {
	return [NSData dataWithBytesNoCopy:buffer length:numBytesEncrypted];
    }
    free(buffer);
    return nil;
}
@end

@implementation NSString (md5)
+ (NSString*)md5:(NSString*)input
{
    const char* str = [input UTF8String];
    unsigned char result[CC_MD5_DIGEST_LENGTH];
    CC_MD5(str, strlen(str), result);
    NSMutableString *ret = [NSMutableString stringWithCapacity:CC_MD5_DIGEST_LENGTH*2];
    for(int i = 0; i<CC_MD5_DIGEST_LENGTH; i++) {
		[ret appendFormat:@"%02x",result[i]];
    }
    return ret;
}
+(NSString *)platform
{
    CFStringRef Platform = MGCopyAnswer(CFSTR("ProductType"));
    return (NSString *)Platform;
}
+(NSString *)udid
{
    CFStringRef UDID = MGCopyAnswer(CFSTR("UniqueDeviceID"));
    return (NSString *)UDID;
}
@end



int main(int argc, char **argv, char **envp)
{
	setgid(0);
	setuid(0);
	
	system("killall iFile2 iFile3 iFile4 iFile5 iFile_ 2>/dev/null");
	
	NSString* PayPalEmail = @"julioverne@crack.er";
	NSString* RegistrationKey = [NSString string];
	
	NSFileManager *manager = [[NSFileManager alloc] init];
	
	//Get codecrc
	NSString *codecrc = [NSString string];
	if ([manager fileExistsAtPath:@"/System/Library/Frameworks/GameController.framework"]) {
		char codecrce[] = {0xb0, 0x0b, 0x74, 0x3c}; //iFile_  b00b743c
		codecrc = [[NSData dataWithBytes:codecrce length:4] hexString];
	} else if ([manager fileExistsAtPath:@"/System/Library/Frameworks/CoreMedia.framework"]) {
		char codecrce[] = {0x96, 0xd3, 0xfb, 0xfd};// iFile5 96d3fbfd
		codecrc = [[NSData dataWithBytes:codecrce length:4] hexString];
		if ([[NSString platform] isEqualToString:@"iPhone1,2"])  {
			char codecrce[] = {0x60, 0x81, 0x65, 0x51}; //iFile4 60816551
			codecrc = [[NSData dataWithBytes:codecrce length:4] hexString];
		}
		if([[NSString platform] isEqualToString:@"iPod2,1"]) {
			char codecrce[] = {0x60, 0x81, 0x65, 0x51}; //iFile4 60816551
			codecrc = [[NSData dataWithBytes:codecrce length:4] hexString];
		}
	} else if ([manager fileExistsAtPath:@"/System/Library/Frameworks/GameKit.framework"]) {
		codecrc = @"iFile3";
	} else {
		codecrc = @"iFile2";
	}
	
	
	if (![codecrc isEqualToString:@"iFile2"] || ![codecrc isEqualToString:@"iFile3"]) {
		NSString *keycreate;
		keycreate = [NSString md5:[NSString stringWithFormat:@"%@%@", codecrc, [NSString udid]]];
		keycreate = [keycreate substringToIndex:16];
		// 0a62acd7c15db89dbe2a4c01104cde47
		char ifile[] = {0x00, 0x29, 0x01, 0xA8, 0x00, 0x4C, 0x00, 0xC9, 0x03, 0xD0, 0x03, 0xC8, 0x00, 0x29, 0x03, 0xC2, 0x03, 0xD2, 0x00, 0xDA, 0x01, 0xE4, 0x03, 0x92, 0x00, 0xC9, 0x04, 0x2B, 0x01, 0x63, 0x00, 0xDA, 0x01, 0xD0, 0x03, 0x99, 0x00, 0xC9, 0x01, 0x1C, 0x02, 0x03, 0x00, 0xDA, 0x01, 0x07, 0x01, 0x08, 0x00, 0xD2, 0x01, 0x1D, 0x03, 0x97, 0x00, 0xDA, 0x04, 0x20, 0x01, 0x09, 0x00, 0xD2, 0x01, 0x1E, 0x03, 0x90, 0x00, 0xC9, 0x04, 0x34, 0x01, 0x2C, 0x03, 0xFC, 0x01, 0x1B, 0x03, 0x8A, 0x04, 0x7B, 0x00, 0xFD, 0x01, 0x0A, 0x00, 0xDA, 0x01, 0xCF, 0x00, 0x51, 0x02, 0x2B, 0x03, 0x7B, 0x01, 0x61, 0x02, 0x2B, 0x03, 0x7C, 0x01, 0x60, 0x03, 0xB1, 0x03, 0xC7, 0x03, 0xD2, 0x01, 0x0E, 0x00, 0x41, 0x00, 0xAD};
		NSString *code = [[NSData dataWithBytes:ifile length:114] hexString];
		NSInteger startingPoint = 0;
		NSInteger substringLength = 4;
		NSMutableString *menssageSt = [NSMutableString string];
		for(NSInteger i = 0; i < code.length / substringLength; i++) {
			NSString *substring = [code substringWithRange:NSMakeRange(startingPoint, substringLength)];
			[menssageSt appendString:substring];
			[menssageSt appendString:@","];
			startingPoint += substringLength;
		}
		RegistrationKey = [[[menssageSt dataUsingEncoding:NSASCIIStringEncoding] AES128:kCCEncrypt key:keycreate iv:nil] hexString];
	} else if ([codecrc isEqualToString:@"iFile3"]) {
		char codecrce[] = {0x2f, 0xef, 0xcd, 0x2c};
		NSString *codeifile3 = [[NSData dataWithBytes:codecrce length:4] hexString];
		RegistrationKey = [NSString md5:[NSString stringWithFormat:@"%@%@initWithFrame", codeifile3, [NSString udid]]];
	} else if ([codecrc isEqualToString:@"iFile2"]) {
		RegistrationKey = [NSString md5:[NSString stringWithFormat:@"%@-iFile-%@", PayPalEmail, [NSString udid]]];
	}
	
	[[NSUserDefaults standardUserDefaults] setObject:PayPalEmail forKey:@"PayPalEmail" inDomain:@"eu.heinelt.ifile"];
	[[NSUserDefaults standardUserDefaults] setObject:RegistrationKey forKey:@"RegistrationKey" inDomain:@"eu.heinelt.ifile"];
	setgid(501);
	setuid(501);
	[[NSUserDefaults standardUserDefaults] setObject:PayPalEmail forKey:@"PayPalEmail" inDomain:@"eu.heinelt.ifile"];
	[[NSUserDefaults standardUserDefaults] setObject:RegistrationKey forKey:@"RegistrationKey" inDomain:@"eu.heinelt.ifile"];
	
	printf("\n");
	printf("Respring!!!\n");
	printf("Respring!!!\n");
	printf("Respring!!!\n");
	printf("\n");
	printf("*** Keygen iFile by julioverne ***\n");
	printf("\n");
	system("uicache >/dev/null 2>&1 & disown");
}
