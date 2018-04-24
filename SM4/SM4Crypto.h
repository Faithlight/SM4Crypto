//
//  SM4.h
//  SM4
//
//  Created by 戴领 on 2018/4/12.
//

#import <Foundation/Foundation.h>
typedef NS_ENUM (NSInteger,Operation) {
    Operaton_Encrypt = 0,
    Operaton_Decrypt = 1
};
typedef NS_ENUM (NSInteger,OptionMode) {
    OptionMode_ECB = 0,
    OptionMode_CBC = 1
};
@interface NSData (SM4Crypto)
- (NSData *)SM4CryptoWithOptionOperation:(Operation)operation optionMode:(OptionMode)mode IV:(NSData *)IVData key:(NSData *)keyData;

@end

@interface NSString (SM4Crypto)
// !important        如果mode = OptionMode_CBC，iv 不能为空                   if mode = OptionMode_CBC, iv can't be nil
- (NSString *)SM4StringEncryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv;
- (NSString *)SM4StringDecryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv;
- (NSString *)SM4FileEncryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv;
- (NSString *)SM4FileDecryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv;
@end


