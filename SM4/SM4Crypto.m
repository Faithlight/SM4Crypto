//
//  SM4.m
//  SM4
//
//  Created by 戴领 on 2018/4/12.
//

#import "SM4Crypto.h"
#include "sm4.h"
#import "SM4+Helper.h"

@implementation NSData (SM4Crypto)
- (NSData *)SM4CryptoWithOptionOperation:(Operation)operation key:(NSData *)keyData mode:(OptionMode)mode optionalIV:(NSData *)ivData optionalPadding:(BOOL)padding
{
    NSAssert(keyData.length ==16 && ivData.length == 16 && self.length > 0, @"参数出错");

    unsigned char key[16] ;
    memcpy(key, keyData.bytes, 16);
    int length = (int)self.length;
    int paddingLength = 0;
    if (operation == Operaton_Encrypt) {
        paddingLength = 16 - length % 16 ;
        length = length +paddingLength;  //位数补齐16倍数
    }
    unsigned char *cInput = (unsigned char*)malloc(length);
    unsigned char* cOutput =(unsigned char*)malloc(length);
    memset(cInput, 0, length);
    memcpy(cInput, self.bytes, self.length);  //原data拷贝
    if (operation == Operaton_Encrypt && padding) {
        for(int i = 0; i < paddingLength; i ++) {
            cInput[self.length +i] = paddingLength;     //将所有填充位填充相同的数paddingLength
        }
    }
        
    sm4_context ctx;
    NSData *cryptData = nil;
    if (operation == Operaton_Encrypt) {
        sm4_setkey_enc(&ctx,key);
    }else{
        sm4_setkey_dec(&ctx,key);
    }
    if (mode == OptionMode_ECB) {
        sm4_crypt_ecb(&ctx, 1-operation, length, cInput, cOutput);
    }else{
        unsigned char iv[16];
        memset(iv, 0, 16);
        memcpy(iv, ivData.bytes, 16);
            // CBC
        sm4_crypt_cbc(&ctx, 1-operation, length,iv, cInput, cOutput);
    }
    if (operation == Operaton_Encrypt) {
        cryptData = [NSData dataWithBytes:cOutput length:length];  //只取原数据长度
    } else {
        if (padding)  paddingLength = cOutput[length -1];
        cryptData = [NSData dataWithBytes:cOutput length:length - paddingLength];
    }
    free(cInput);
    free(cOutput);
    cInput = NULL;
    cOutput = NULL;
    return cryptData;
}
@end

@implementation NSString (SM4Crypto)
- (NSString *)SM4StringEncryptWithKey:(NSString *__nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv optionalPadding:(BOOL)padding
{
//    NSAssert(key.length ==16 && iv.length == 16 && self.length > 0, @"参数出错");

    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char cKey[16] ;
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
    int length = (int)data.length;
    int paddingLength = 0;
    paddingLength =  16 - length % 16;
    length = length +paddingLength;  //补齐16倍数
    unsigned char *cInput = (unsigned char*)malloc(length);
    unsigned char* cOutput =(unsigned char*)malloc(length);
    memset(cInput, 0, length);
    memcpy(cInput, data.bytes, data.length);  //原data拷贝
    if (padding) {
        for(int i = 0; i < paddingLength; i ++) {
                cInput[data.length +i] = paddingLength;     //将所有填充位填充相同的数paddingLength
        }
    }
    sm4_context ctx;
    sm4_setkey_enc(&ctx,cKey);
    if (mode == OptionMode_ECB) {
        sm4_crypt_ecb(&ctx, 1, length, cInput, cOutput);
    }else{
        unsigned char cIV[16];
        memcpy(cIV, [iv dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
            // CBC
        sm4_crypt_cbc(&ctx, 1, length,cIV, cInput, cOutput);
    }
    NSData *cryptData = [NSData dataWithBytes:cOutput length:length];
    free(cInput);
    free(cOutput);
    cInput = NULL;
    cOutput = NULL;
//    转base64编码string，对应的解密时候也需要用base64解码成data
    return [cryptData base64EncodedStringWithOptions:0];
//    return cryptData.HexString;
}
- (NSString *)SM4StringDecryptWithKey:(NSString *__nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv optionalPadding:(BOOL)padding
{
//    NSAssert(key.length ==16 && iv.length == 16 && self.length > 0, @"参数出错");

    NSData *data = [[NSData alloc]  initWithBase64EncodedString:self options:0];
//    NSData *data = [self hexStringRestoreData];
    unsigned char cKey[16] ;
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
    int length = (int)data.length;
    int paddingLength = 0;

    unsigned char *cInput = (unsigned char*)malloc(length);
    unsigned char* cOutput =(unsigned char*)malloc(length);
    memset(cInput, 0, length);
    memcpy(cInput, data.bytes, data.length);  //原data拷贝
    
    sm4_context ctx;
    sm4_setkey_dec(&ctx,cKey);
    if (mode == OptionMode_ECB) {
        sm4_crypt_ecb(&ctx, 0, length, cInput, cOutput);
    }else{
        unsigned char cIV[16];
        memcpy(cIV, [iv dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
            // CBC
        sm4_crypt_cbc(&ctx, 0, length,cIV, cInput, cOutput);
    }
    if (padding ) {
        paddingLength = cOutput[length -1];
    }
    NSData *cryptData = [NSData dataWithBytes:cOutput length:length - paddingLength];
    free(cInput);
    free(cOutput);
    cInput = NULL;
    cOutput = NULL;
    return [[NSString alloc] initWithData:cryptData encoding:NSUTF8StringEncoding];
}



- (NSString *)SM4FileEncryptWithKey:(NSString * __nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv
{
    NSAssert(key.length ==16 && iv.length == 16 && self.length > 0, @"参数出错");

    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:self];
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [inputStream open];
    NSString *outputPath = [self stringByAppendingPathExtension:@"sm4"];   //设置加密后缀
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
    
    unsigned char cKey[16] ;
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
        //读取的字节长度
    NSInteger maxLength = 1024*1024;
        //缓冲区
    uint8_t readBuffer [maxLength];
    sm4_context ctx;   //初始化sm4 ctx
    sm4_setkey_enc(&ctx,cKey);
    while (inputStream.hasBytesAvailable) {
        @autoreleasepool {   //自动释放池释放buffData等数据
                //从输出流中读取数据，读到缓冲区中
            NSInteger bytesRead = [inputStream read: readBuffer
                                               maxLength:maxLength];
            NSLog(@"%ld",(long)bytesRead);
                //如果长度大于0就追加数据
            if (bytesRead > 0)
                {
                NSData *buffData = [NSData dataWithBytes:readBuffer length:bytesRead];
                int length = (int)buffData.length;
                unsigned char *cInput = (unsigned char*)malloc(length);
                unsigned char* cOutput =(unsigned char*)malloc(length);
                memset(cInput, 0, length);
                memcpy(cInput, buffData.bytes, buffData.length);  //原data拷贝
                if (mode == OptionMode_ECB) {
                    sm4_crypt_ecb(&ctx, 1, length, cInput, cOutput);
                }else{
                        // CBC
                    unsigned char cIV[16];
                    memcpy(cIV, [iv dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
                    sm4_crypt_cbc(&ctx, 1, length,cIV, cInput, cOutput);
                }
                NSData *cryptData = [NSData dataWithBytes:cOutput length:length];
                free(cInput);
                free(cOutput);
                cInput = NULL;
                cOutput = NULL;
                [outputStream write:cryptData.bytes maxLength:cryptData.length];
                }
        }
    }
    [inputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    [outputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    return outputPath;
}
- (NSString *)SM4FileDecryptWithKey:(NSString *__nonnull)key mode:(OptionMode)mode optionalIV:(NSString *)iv
{
    NSAssert(key.length ==16 && iv.length == 16 && self.length > 0, @"参数出错");

    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:self];
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [inputStream open];
    NSString *outputPath = [self stringByDeletingPathExtension];   //解密去除后缀
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
    
    unsigned char cKey[16] ;
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
        //读取的字节长度
    NSInteger maxLength = 1024*1024;
        //缓冲区
    uint8_t readBuffer [maxLength];
    sm4_context ctx;
    sm4_setkey_dec(&ctx,cKey);
    while (inputStream.hasBytesAvailable) {
        @autoreleasepool {
                //从输出流中读取数据，读到缓冲区中
            NSInteger bytesRead = [inputStream read: readBuffer
                                          maxLength:maxLength];
            NSLog(@"%ld",(long)bytesRead);
                //如果长度大于0就追加数据
            if (bytesRead > 0)
                {
                NSData *buffData = [NSData dataWithBytes:readBuffer length:bytesRead];
                int length = (int)buffData.length;
                unsigned char *cInput = (unsigned char*)malloc(length);
                unsigned char *cOutput =(unsigned char*)malloc(length);
                memset(cInput, 0, length);
                memcpy(cInput, buffData.bytes, buffData.length);  //原data拷贝
                if (mode == OptionMode_ECB) {
                    sm4_crypt_ecb(&ctx, 0, length, cInput, cOutput);
                }else{
                        // CBC
                    unsigned char cIV[16];
                    memcpy(cIV, [iv dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
                    sm4_crypt_cbc(&ctx, 0, length,cIV, cInput, cOutput);
                }
                NSData *cryptData = [NSData dataWithBytes:cOutput length:length];

                free(cInput);
                free(cOutput);
                cInput = NULL;
                cOutput = NULL;
                [outputStream write:cryptData.bytes maxLength:cryptData.length];
                }
        }
    }
    [inputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    [outputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    return outputPath;
}
@end
