//
//  SM4.h
//  SM4
//
//  Created by 戴领 on 2018/4/12.
//

#import <Foundation/Foundation.h>
typedef NS_ENUM (NSInteger,CryptoMode) { //加密模式
    CryptoMode_ECB = 0,
    CryptoMode_CBC
};

typedef NS_ENUM (NSInteger,PaddingType) { //填充模式
    PaddingType_None = 0, //不处理
    PaddingType_Zero, //填充0
    PaddingType_PKCS5,  //填充补充长度
    PaddingType_PKCS7,  //同上
    PaddingType_ISO10126,//最后一位填充补充长度,其他随机
    PaddingType_ANSIX923, //最后一位填充补充长度,其他为0
    PaddingType_0x80, //第一个填充0x80,其他为0
};

//SM4为分组加密模式,一组大小16字节
//当一组明文被加密但长度又不满足一组时,需要填充(padding)至一组
// !!! important
// key can't be nil, and lenth must 16
// if mode is OptionMode_CBC, iv can't be nil, and lenth must 16
//PaddingOptions: PKCS7 && ZeroPadding

@interface NSData (SM4DataCrypto)
- (NSData *)SM4EncryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType;
- (NSData *)SM4DecryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType;
@end

@interface NSString (SM4StringCrypto)
- (NSString *)SM4EncryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType;
- (NSString *)SM4DecryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType;

@end

@interface NSString (SM4FileCrypto)
- (NSString *)fileStreamSM4EncryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv;
- (NSString *)fileStreamSM4DecryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv;
@end
