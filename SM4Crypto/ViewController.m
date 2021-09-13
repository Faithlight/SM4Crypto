//
//  ViewController.m
//  SM4Crypto
//
//  Created by 戴领 on 2021/9/3.
//

#import "ViewController.h"
#import "SM4Crypto.h"
@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    // Do any additional setup after loading the view.
    NSString *inputpath = [NSBundle.mainBundle pathForResource:@"孟庭苇 - 风中有朵雨做的云" ofType:@"mp3"];
    [NSFileManager.defaultManager moveItemAtPath:inputpath toPath:[NSHomeDirectory() stringByAppendingPathComponent:@"a.mp3"] error:nil];
    
    [self stringCrypt];
    [self fileStreamCrypt];
    
    



}


- (void)stringCrypt {
    NSString *test = @"3256ysfdgfdh";
    NSString *key = @"3245678543234567";
    NSString *encryptString = [self encryptString:test withKey:key mode:CryptoMode_ECB optionalIV:nil paddingType:PaddingType_Zero];
    NSLog(@"encryptString = %@",encryptString);
    NSString *decryptString = [self decryptString:encryptString withKey:key mode:CryptoMode_ECB optionalIV:nil paddingType:PaddingType_Zero];
    NSLog(@"decryptString = %@",decryptString);
}

- (NSString *)encryptString:(NSString *)string withKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType
{
    NSData *plainData = [string dataUsingEncoding:NSUTF8StringEncoding];
    NSData *encryptData = [plainData dataSM4EncryptWithKey:key mode:mode optionalIV:iv paddingType:paddingType];
//    转base64编码string，对应的解密时候也需要用base64解码成data
    return [encryptData base64EncodedStringWithOptions:0];
//    return cryptData.HexString; //也可以生成16进制字符串
}

- (NSString *)decryptString:(NSString *)string withKey:(NSString *)key mode:(CryptoMode)mode optionalIV:(NSString *)iv paddingType:(PaddingType)paddingType
{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:string options:0];
//    NSData *data = [self hexStringRestoreData];
    NSData *decryptData = [data dataSM4DecryptWithKey:key mode:mode optionalIV:iv paddingType:paddingType];
    return [[NSString alloc] initWithData:decryptData encoding:NSUTF8StringEncoding];
}



- (void)fileStreamCrypt {
    NSString *key = @"3245678543234567";
    NSString * inputpath = [NSHomeDirectory() stringByAppendingPathComponent:@"a.mp3"];
    NSString *encryptPath = [inputpath fileStreamSM4EncryptWithKey:key mode:CryptoMode_ECB optionalIV:nil];
    [NSFileManager.defaultManager removeItemAtPath:inputpath error:nil];
    NSLog(@"%@",encryptPath);
    NSString *decryptPath = [encryptPath fileStreamSM4DecryptWithKey:key mode:CryptoMode_ECB optionalIV:nil];
    NSLog(@"%@",decryptPath);
    [NSFileManager.defaultManager removeItemAtPath:encryptPath error:nil];
}
@end
