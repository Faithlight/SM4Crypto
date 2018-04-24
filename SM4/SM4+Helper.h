//
//  SM4+Helper.h
//  SM4Crypto
//
//  Created by 戴领 on 2018/4/23.
//  Copyright © 2018年 戴领. All rights reserved.
//


#import <Foundation/Foundation.h>
@interface NSData (HexString)
- (NSString *)HexString;
@end
@interface NSString (HexData)
- (NSData *)hexStringRestoreData;
@end
