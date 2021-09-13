//
//  SM4.m
//  SM4
//
//  Created by 戴领 on 2018/4/12.
//

#import "SM4Crypto.h"
#include "sm4.h"

#pragma mark DataCrypto

@implementation NSData (SM4DataCrypto)
- (NSData *)dataSM4EncryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType
{
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    NSParameterAssert(iv == nil || [iv isKindOfClass: [NSData class]] || [iv isKindOfClass: [NSString class]]);
    NSMutableData *keyData = nil,*ivData = nil;
    if ([key isKindOfClass: [NSData class]]) {
        keyData = (NSMutableData *) [key mutableCopy];
    } else if ([key isKindOfClass: [NSString class]]) {
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    if ([iv isKindOfClass: [NSData class]]) {
        ivData = (NSMutableData *) [iv mutableCopy];
    } else if ([iv isKindOfClass: [NSString class]]) {
        ivData = [[iv dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    NSData *plainData = self;
    uint8_t blockSize = 16;
    //padding
    plainData = [plainData paddingWithType:paddingType blockSize:blockSize];
    NSUInteger length = plainData.length;
    //key iv
    unsigned char *cKey = (unsigned char*)malloc(blockSize);
    if (keyData)  memcpy(cKey, keyData.bytes, blockSize);
    unsigned char *cIV = (unsigned char*)malloc(blockSize);
    if (ivData)  memcpy(cIV, ivData.bytes, blockSize);
    //input
    unsigned char *cInput = (unsigned char*)malloc(length);
    memcpy(cInput, plainData.bytes, length);  //原data拷贝
    //key output
    unsigned char *cOutput = (unsigned char*)malloc(length);
    //SM4
    sm4_context ctx;
    sm4_setkey_enc(&ctx,cKey);
    if (mode == CryptoMode_ECB) {
        sm4_crypt_ecb(&ctx, 1, (int)length, cInput, cOutput);
    } else if (mode == CryptoMode_CBC) {
        sm4_crypt_cbc(&ctx, 1, (int)length, cIV, cInput, cOutput);
    }
    NSData *cryptData = [NSData dataWithBytes:cOutput length:length];
    free(cInput);
    free(cKey);
    free(cIV);
    free(cOutput);
    cInput = NULL;
    cKey = NULL;
    cIV = NULL;
    cOutput = NULL;
    return cryptData;
}
- (NSData *)dataSM4DecryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv paddingType:(PaddingType)paddingType
{
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    NSParameterAssert(iv == nil || [iv isKindOfClass: [NSData class]] || [iv isKindOfClass: [NSString class]]);
    NSMutableData *keyData = nil,*ivData = nil;
    if ([key isKindOfClass: [NSData class]]) {
        keyData = (NSMutableData *) [key mutableCopy];
    } else if ([key isKindOfClass: [NSString class]]) {
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    if ([iv isKindOfClass: [NSData class]]) {
        ivData = (NSMutableData *) [iv mutableCopy];
    } else if ([iv isKindOfClass: [NSString class]]) {
        ivData = [[iv dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    NSData *cryptData = self;
    uint8_t blockSize = 16;
    NSUInteger length = cryptData.length;
    //key iv
    unsigned char *cKey = (unsigned char*)malloc(blockSize);
    if (keyData)  memcpy(cKey, keyData.bytes, blockSize);
    unsigned char *cIV = (unsigned char*)malloc(blockSize);
    if (ivData)  memcpy(cIV, ivData.bytes, blockSize);
    //input output
    unsigned char *cInput = (unsigned char*)malloc(length);
    memcpy(cInput, cryptData.bytes, length);  //原data拷贝
    unsigned char *cOutput = (unsigned char*)malloc(length);
    //SM4
    sm4_context ctx;
    sm4_setkey_dec(&ctx,cKey);
    if (mode == CryptoMode_ECB) {
        sm4_crypt_ecb(&ctx, 1, (int)length, cInput, cOutput);
    } else if (mode == CryptoMode_CBC) {
        sm4_crypt_cbc(&ctx, 1, (int)length, cIV, cInput, cOutput);
    }
    NSData *plainData = [NSData dataWithBytes:cOutput length:length];
    
    free(cInput);
    free(cKey);
    free(cIV);
    free(cOutput);
    cInput = NULL;
    cKey = NULL;
    cIV = NULL;
    cOutput = NULL;
    return [plainData unPaddingWithType:paddingType];
}


- (NSData *)paddingWithType:(PaddingType)type blockSize:(uint8_t)blockSize
{
    //补位存储数据
    uint8_t cPaddingData[512]={0};
    //获取需要补位长度 bytes
    uint8_t paddingLen =  blockSize - self.length % blockSize;
    //fill padding
    NSData *paddedData = nil;
    switch (type) {
        case PaddingType_None:
            paddedData = self;
            break;
        case PaddingType_PKCS5:
        case PaddingType_PKCS7:  {
                //PKCS5:只支持分组长度为8bytes的, PKCS7:支持分组长度1-128bytes,这里当作同一个算法处理了
            memset(cPaddingData, paddingLen, paddingLen);
            NSMutableData *data = [[NSMutableData alloc]initWithCapacity:self.length + paddingLen];
            [data appendData:self];
            [data appendBytes:cPaddingData length:paddingLen];
            paddedData = data;
        }
            break;
        case PaddingType_Zero: {
            memset(cPaddingData, 0x00, paddingLen);
            NSMutableData *data = [[NSMutableData alloc]initWithCapacity:self.length + paddingLen];
            [data appendData:self];
            [data appendBytes:cPaddingData length:paddingLen];
            paddedData = data;
        }
            break;
        case PaddingType_0x80: {
            NSInteger diffBits = (self.length + 1) % blockSize;
            if (diffBits == 0) {
                    //仅仅添加0x80一个字节即可
                paddingLen = 1;
                memset(cPaddingData, 0x80, paddingLen);
                NSMutableData *data = [[NSMutableData alloc]initWithCapacity:self.length + paddingLen];
                [data appendData:self];
                [data appendBytes:cPaddingData length:paddingLen];
                paddedData = data;
                
            }else{
                paddingLen = blockSize - diffBits;
                
                memset(cPaddingData, 0x80, 1);
                memset(cPaddingData+1, 0x00, paddingLen);
                NSMutableData *data = [[NSMutableData alloc]initWithCapacity:self.length + paddingLen + 1];
                [data appendData:self];
                [data appendBytes:cPaddingData length:paddingLen+1];
                paddedData = data;
            }
        }
            break;
        case PaddingType_ANSIX923: {
                //最后一位表示补位的长度，其他位置0x00
            memset(cPaddingData, 0x00, paddingLen);
            cPaddingData[paddingLen-1] = paddingLen;
            NSMutableData *data = [[NSMutableData alloc]initWithCapacity:self.length + paddingLen];
            [data appendData:self];
            [data appendBytes:cPaddingData length:paddingLen];
            paddedData = data;
        }
            break;
        case PaddingType_ISO10126: {
                //最后一位表示填充的长度，其他字节随机
            for (int i = 0; i < paddingLen-1; i++) {
                cPaddingData[i] = arc4random() % 256;
            }
            cPaddingData[paddingLen-1] = paddingLen;
            NSMutableData *data = [[NSMutableData alloc]initWithCapacity:self.length + paddingLen];
            [data appendData:self];
            [data appendBytes:cPaddingData length:paddingLen];
            paddedData = data;
        }
            break;
        default:
            break;
    }
    
    return paddedData;
}

- (NSData*)unPaddingWithType:(PaddingType)type
{
   //unPad data
    NSData *unPaddedData = nil;
    //补位长度 bytes
    uint16_t paddingLen =  0;
    //解密后的数据
    uint8_t *bytes = (uint8_t*)self.bytes;
    switch (type) {
        case PaddingType_None:
            unPaddedData = self;
            break;
        case PaddingType_PKCS5:
        case PaddingType_PKCS7:
        case PaddingType_ANSIX923:
        case PaddingType_ISO10126: {
                //都是最后一个字节表示补位的长度
            NSInteger datalen = self.length;
            paddingLen = bytes[datalen-1];
            if (paddingLen >= self.length ) {
                return nil;
            }
            unPaddedData = [NSData dataWithBytes:self.bytes length:self.length - paddingLen];
        }
            break;
        case PaddingType_Zero: {
            uint8_t *pBytes = bytes+self.length-1;
            paddingLen = 0;
            do {
                if ( *pBytes != 0x00 ) {
                    break;
                }
                pBytes -= 1;
                paddingLen += 1;
            } while (paddingLen < self.length);
            unPaddedData = [NSData dataWithBytes:self.bytes length:self.length - paddingLen];
        }
            break;
        case PaddingType_0x80: {
            uint8_t *pBytes = bytes+self.length-1;
            paddingLen = 0;
            do {
                if ( *pBytes == 0x80 ) {
                    break;
                }
                pBytes -= 1;
                paddingLen += 1;
            } while (paddingLen < self.length);
            paddingLen += 1;
            unPaddedData = [NSData dataWithBytes:self.bytes length:self.length - paddingLen];
        }
            break;
        default:
            break;
    }
    
    return unPaddedData;
}
@end




#pragma mark FileCrypto

@implementation NSString (SM4FileCrypto)

- (NSString *)fileStreamSM4EncryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv
{
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    NSParameterAssert(iv == nil || [iv isKindOfClass: [NSData class]] || [iv isKindOfClass: [NSString class]]);
    NSMutableData *keyData = nil,*ivData = nil;
    if ([key isKindOfClass: [NSData class]]) {
        keyData = (NSMutableData *) [key mutableCopy];
    } else if ([key isKindOfClass: [NSString class]]) {
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    if ([iv isKindOfClass: [NSData class]]) {
        ivData = (NSMutableData *) [iv mutableCopy];
    } else if ([iv isKindOfClass: [NSString class]]) {
        ivData = [[iv dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    
    //准备stream
    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:self];
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [inputStream open];
    NSString *outputPath = [self stringByAppendingPathExtension:@"sm4"];   //设置加密后缀
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
    
    unsigned char cKey[16];//秘钥
    memcpy(cKey, keyData.bytes, 16);
    unsigned char cIV[16]; //iv
    if (ivData) memcpy(cIV, ivData.bytes, 16);
    NSInteger maxLength = 1024*1024;//每次读取的字节长度
    uint8_t readBuffer[maxLength]; //buff缓冲区
    
    sm4_context ctx;   //初始化sm4 ctx
    sm4_setkey_enc(&ctx,cKey);
    while (inputStream.hasBytesAvailable) {
        @autoreleasepool {   //自动释放池释放buffData等数据
            //从输出流中读取数据，读到缓冲区中
            NSInteger bytesRead = [inputStream read:readBuffer maxLength:maxLength];
            if (bytesRead > 0) {                 //如果长度大于0就加密数据
                NSData *buffData = [NSData dataWithBytes:readBuffer length:bytesRead];
                int length = (int)buffData.length;
                unsigned char *cInput = (unsigned char*)malloc(length);
                unsigned char* cOutput = (unsigned char*)malloc(length);
                memset(cInput, 0, length);//文件加密不考虑padding,置0
                memcpy(cInput, buffData.bytes, buffData.length);  //原data拷贝
                if (mode == CryptoMode_ECB) {
                    sm4_crypt_ecb(&ctx, 1, length, cInput, cOutput);
                }else if (mode == CryptoMode_CBC) {
                    sm4_crypt_cbc(&ctx, 1, length, cIV, cInput, cOutput);
                }
                NSData *cryptData = [NSData dataWithBytes:cOutput length:length];
                [outputStream write:cryptData.bytes maxLength:cryptData.length];
                free(cInput);
                free(cOutput);
                cInput = NULL;
                cOutput = NULL;
            }
        }
    }
    [inputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    [outputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    return outputPath;
}
- (NSString *)fileStreamSM4DecryptWithKey:(id)key mode:(CryptoMode)mode optionalIV:(id)iv
{
    NSParameterAssert([key isKindOfClass: [NSData class]] || [key isKindOfClass: [NSString class]]);
    NSParameterAssert(iv == nil || [iv isKindOfClass: [NSData class]] || [iv isKindOfClass: [NSString class]]);
    NSMutableData *keyData = nil,*ivData = nil;
    if ([key isKindOfClass: [NSData class]]) {
        keyData = (NSMutableData *) [key mutableCopy];
    } else if ([key isKindOfClass: [NSString class]]) {
        keyData = [[key dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }
    if ([iv isKindOfClass: [NSData class]]) {
        ivData = (NSMutableData *) [iv mutableCopy];
    } else if ([iv isKindOfClass: [NSString class]]) {
        ivData = [[iv dataUsingEncoding: NSUTF8StringEncoding] mutableCopy];
    }

    //准备stream
    NSInputStream *inputStream = [[NSInputStream alloc] initWithFileAtPath:self];
    [inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [inputStream open];
    NSString *outputPath = [self stringByDeletingPathExtension];   //解密去除后缀
    NSOutputStream *outputStream = [[NSOutputStream alloc] initToFileAtPath:outputPath append:YES];
    [outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [outputStream open];
    
    unsigned char cKey[16];
    memcpy(cKey, keyData.bytes, 16);
    unsigned char cIV[16]; //iv
    if (ivData) memcpy(cIV, ivData.bytes, 16);
    NSInteger maxLength = 1024*1024;
    uint8_t readBuffer [maxLength];
    
    sm4_context ctx;
    sm4_setkey_dec(&ctx,cKey);
    while (inputStream.hasBytesAvailable) {
        @autoreleasepool {
            NSInteger bytesRead = [inputStream read: readBuffer
                                          maxLength:maxLength];
            if (bytesRead > 0) {
                NSData *buffData = [NSData dataWithBytes:readBuffer length:bytesRead];
                int length = (int)buffData.length;
                unsigned char *cInput = (unsigned char*)malloc(length);
                unsigned char *cOutput = (unsigned char*)malloc(length);
                memset(cInput, 0, length);
                memcpy(cInput, buffData.bytes, buffData.length);
                if (mode == CryptoMode_ECB) {
                    sm4_crypt_ecb(&ctx, 0, length, cInput, cOutput);
                }else if (mode == CryptoMode_CBC) {
                    sm4_crypt_cbc(&ctx, 0, length, cIV, cInput, cOutput);
                }
                NSData *cryptData = [NSData dataWithBytes:cOutput length:length];
                [outputStream write:cryptData.bytes maxLength:cryptData.length];
                free(cInput);
                free(cOutput);
                cInput = NULL;
                cOutput = NULL;
            }
        }
    }
    [inputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    [outputStream removeFromRunLoop:NSRunLoop.currentRunLoop forMode:NSDefaultRunLoopMode];
    return outputPath;
}

@end
