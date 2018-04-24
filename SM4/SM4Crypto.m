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
- (NSData *)SM4CryptoWithOptionOperation:(Operation)operation optionMode:(OptionMode)mode IV:(NSData *)IVData key:(NSData *)keyData
{
    
    unsigned char key[16] = {0x00};
    memcpy(key, keyData.bytes, 16);
    int length = (int)self.length;
    int paddingLength = 0;
    
    if (operation == Operaton_Encrypt) {
        paddingLength =16 - length % 16;
        length = length +paddingLength;   //padding填充后的长度，为16的倍数
    }
    unsigned char *cInput = (unsigned char*)malloc(length);
    unsigned char* cOutput =(unsigned char*)malloc(length);
    memset(cInput, 0, length);
    memcpy(cInput, self.bytes, self.length);  //原data拷贝
    if (operation == Operaton_Encrypt) {
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
        memcpy(iv, IVData.bytes, 16);
            // CBC
        sm4_crypt_cbc(&ctx, 1-operation, length,iv, cInput, cOutput);
    }
    if (operation == Operaton_Encrypt) {
        cryptData = [NSData dataWithBytes:cOutput length:length];  //只取原数据长度
    } else {
        paddingLength = cOutput[length -1];
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
- (NSString *)SM4StringEncryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv
{
    NSData *data = [self dataUsingEncoding:NSUTF8StringEncoding];
    unsigned char cKey[16] = {0x00};
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
    int length = (int)data.length;
    int paddingLength = 0;
    paddingLength =16 - length % 16;
    length = length +paddingLength;   //padding填充后的长度，为16的倍数
    
    unsigned char *cInput = (unsigned char*)malloc(length);
    unsigned char* cOutput =(unsigned char*)malloc(length);
    memset(cInput, 0, length);
    memcpy(cInput, data.bytes, data.length);  //原data拷贝
    for(int i = 0; i < paddingLength; i ++) {
        cInput[data.length +i] = paddingLength;     //将所有填充位填充相同的数paddingLength
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
//    return [[NSString alloc] initWithData:[cryptData base64EncodedDataWithOptions:0] encoding:NSUTF8StringEncoding];
    return cryptData.HexString;
}
- (NSString *)SM4StringDecryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv
{
//    NSData *data = [[NSData alloc]  initWithBase64EncodedString:self options:0];
    NSData *data = [self hexStringRestoreData];
    unsigned char cKey[16] = {0x00};
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
    paddingLength = cOutput[length -1];
    NSData *cryptData = [NSData dataWithBytes:cOutput length:length - paddingLength];
    free(cInput);
    free(cOutput);
    cInput = NULL;
    cOutput = NULL;
    return [[NSString alloc] initWithData:cryptData encoding:NSUTF8StringEncoding];
}



- (NSString *)SM4FileEncryptWithkey:(NSString * __nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv
{
    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:self];
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [inputStream open];
    NSString *outputPath = [self stringByAppendingPathExtension:@"sm4"];   //设置加密后缀
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
    
    unsigned char cKey[16] = {0x00};
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
        //读取的字节长度
    NSInteger maxLength = 1024*1024;
        //缓冲区
    uint8_t readBuffer [maxLength];
    sm4_context ctx;   //初始化sm4 ctx
    sm4_setkey_enc(&ctx,cKey);
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
                int paddingLength = 0;
                paddingLength =16 - length % 16;
                length = length +paddingLength;   //padding填充后的长度，为16的倍数

                unsigned char *cInput = (unsigned char*)malloc(length);
                unsigned char* cOutput =(unsigned char*)malloc(length);
                memset(cInput, 0, length);
                memcpy(cInput, buffData.bytes, buffData.length);  //原data拷贝
                for(int i = 0; i < paddingLength; i ++) {
                    cInput[buffData.length +i] = paddingLength;     //将所有填充位填充相同的数paddingLength
                }
                
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
- (NSString *)SM4FileDecryptWithkey:(NSString *__nonnull)key optionMode:(OptionMode)mode optionalIV:(NSString *)iv
{
    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:self];
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [inputStream open];
    NSString *outputPath = [self stringByDeletingPathExtension];   //解密去除后缀
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
    
    unsigned char cKey[16] = {0x00};
    memcpy(cKey, [key dataUsingEncoding:NSUTF8StringEncoding].bytes, 16);
        //读取的字节长度
    NSInteger maxLength = 1024*1024 +16;
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
                int paddingLength = 0;
                
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
                paddingLength = cOutput[length -1];
                NSData *cryptData = [NSData dataWithBytes:cOutput length:length-paddingLength];
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
