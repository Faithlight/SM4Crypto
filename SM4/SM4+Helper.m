//
//  SM4+Helper.m
//  SM4Crypto
//
//  Created by 戴领 on 2018/4/23.
//  Copyright © 2018年 戴领. All rights reserved.
//

#import "SM4+Helper.h"

@implementation NSData (HexString)   //不要用于大文件的处理 ------因为会循环遍历
- (NSString *)HexString {   //16进制编码
    Byte *bytes = (Byte *)[self bytes];
        // 下面是Byte 转换为16进制。
    NSString *hexStr = @"";
    for(int i=0; i<[self length]; i++) {
        NSString *newHexStr = [NSString stringWithFormat:@"%x",bytes[i] & 0xff]; //16进制数
        newHexStr = [newHexStr uppercaseString];
        
        if([newHexStr length] == 1) {
            newHexStr = [NSString stringWithFormat:@"0%@",newHexStr];
        }
        
        hexStr = [hexStr stringByAppendingString:newHexStr];
        
    }
    return hexStr;
}
@end
    //↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑
    // 用于将加密过后的data转换成可显示的16进制字符串
    //类比utf8编码，只有先编码在解码，HexString类似编码，HexData类似解码
    // 反之
    //↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
@implementation NSString (HexData)
- (NSData *)hexStringRestoreData      //字符串转成16进制的data数据
{
    if (self == nil) {
        
        return nil;
    }
    
    const char* ch = [[self lowercaseString] cStringUsingEncoding:NSUTF8StringEncoding];
    NSMutableData* data = [NSMutableData data];
    while (*ch) {
        if (*ch == ' ') {
            continue;
        }
        char byte = 0;
        if ('0' <= *ch && *ch <= '9') {
            
            byte = *ch - '0';
        }else if ('a' <= *ch && *ch <= 'f') {
            
            byte = *ch - 'a' + 10;
        }else if ('A' <= *ch && *ch <= 'F') {
            
            byte = *ch - 'A' + 10;
            
        }
        
        ch++;
        
        byte = byte << 4;
        
        if (*ch) {
            
            if ('0' <= *ch && *ch <= '9') {
                
                byte += *ch - '0';
                
            } else if ('a' <= *ch && *ch <= 'f') {
                
                byte += *ch - 'a' + 10;
                
            }else if('A' <= *ch && *ch <= 'F'){
                
                byte += *ch - 'A' + 10;
                
            }
            
            ch++;
            
        }
        
        [data appendBytes:&byte length:1];
        
    }
    
    return data;
}
@end
