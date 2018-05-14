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
- (NSData *)SM4CryptoWithOptionOperation:(Operation)operation key:(NSData *)keyData mode:(OptionMode)mode optionalIV:(NSData *)ivData optionalPadding:(BOOL)padding;

@end

@interface NSString (SM4Crypto)
// !!! important                if mode = OptionMode_CBC, iv can't be nil
- (NSString *)SM4StringEncryptWithKey:(NSString *__nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv optionalPadding:(BOOL)padding;
- (NSString *)SM4StringDecryptWithKey:(NSString *__nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv optionalPadding:(BOOL)padding;
- (NSString *)SM4FileEncryptWithKey:(NSString * __nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv;
- (NSString *)SM4FileDecryptWithKey:(NSString *__nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv;
@end


