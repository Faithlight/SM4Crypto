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
    [self fileStreamCrypt];
    
    



}
- (void)crypt {
    NSString *test = @"3256ysfdgfdh";
    NSString *key = @"3245678543234567";
    NSString *encryptString = [test SM4EncryptWithKey:key mode:CryptoMode_ECB optionalIV:nil paddingType:PaddingType_Zero];
    NSLog(@"encryptString = %@",encryptString);
    NSString *decryptString = [encryptString SM4DecryptWithKey:key mode:CryptoMode_ECB optionalIV:nil paddingType:PaddingType_Zero];
    NSLog(@"decryptString = %@",decryptString);
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
