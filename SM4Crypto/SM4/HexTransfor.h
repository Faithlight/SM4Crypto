//
//  HexTransfor.h
//  SM4Crypto
//
//  Created by dl on 2018/4/23.
//  Copyright © 2018年 dl. All rights reserved.
//


#import <Foundation/Foundation.h>
//类比base64编解码
@interface NSData (HexString)
- (NSString *)HexString;
@end

@interface NSString (HexData)
- (NSData *)hexStringRestoreData;
@end
