//
//  Tools.h
//  PCSC-UI
//
//  Created by 刘维凯 on 2018/9/20.
//  Copyright © 2018年 刘维凯. All rights reserved.
//

#import <Foundation/Foundation.h>
#import "PCSC/winscard.h"
#import <CommonCrypto/CommonCryptor.h>

@interface Tools : NSObject
+ (BOOL)isNullToString:(id)string;
+ (NSString *)ByteToString:(unsigned char *)inData;
+ (NSString *)ByteToString:(unsigned char *)inData andDataLen:(uint32_t)len;
+ (NSData*)stringToByte:(NSString*)string;

/*
 * DES方式实用
 */
+ (NSString *) encryptUseDES:(NSString *)clearText key:(NSString *)key;//加密

/*
 * 3DES方式
 */
+ (NSString*)TripleDES:(NSString*)plainText key:(NSString *)key encryptOrDecrypt:(CCOperation)encryptOrDecrypt;
@end
